package vless

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/gofrs/uuid/v5"
	"google.golang.org/protobuf/proto"
)

const testUUID = "b831381d-6324-4d53-ad4f-8cda48b30811"

// requestBytes returns exactly what a VLESS client writes for its first
// payload — the full request header plus payload.
func requestBytes(t *testing.T, addons *Addons, payload []byte) []byte {
	t.Helper()
	client, err := NewClient(testUUID, addons)
	if err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	dst := &DstAddr{AddrType: AtypDomainName, Addr: append([]byte{11}, "example.com"...), Port: 443}
	conn, err := client.StreamConn(a, dst)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 512)
		n, _ := io.ReadAtLeast(b, buf, 1)
		got <- buf[:n]
	}()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	return <-got
}

// goldenRequest is the pre-YueLink wire format, written out by hand.
func goldenRequest(addons []byte, payload []byte) []byte {
	id := uuid.FromStringOrNil(testUUID)
	var w bytes.Buffer
	w.WriteByte(Version)
	w.Write(id.Bytes())
	w.WriteByte(byte(len(addons)))
	w.Write(addons)
	w.WriteByte(CommandTCP)
	w.Write([]byte{0x01, 0xbb}) // 443
	w.WriteByte(AtypDomainName)
	w.WriteByte(11)
	w.WriteString("example.com")
	w.Write(payload)
	return w.Bytes()
}

func TestYueConnTagOffIsByteIdentical(t *testing.T) {
	payload := []byte("hello")
	// No tag: the helper must hand back the very same pointer.
	if WithYueConnTag(nil, "") != nil {
		t.Fatal("empty tag must keep nil addons nil")
	}
	flow := &Addons{Flow: XRV}
	if WithYueConnTag(flow, "") != flow {
		t.Fatal("empty tag must return addons unchanged")
	}
	got := requestBytes(t, WithYueConnTag(nil, ""), payload)
	if want := goldenRequest(nil, payload); !bytes.Equal(got, want) {
		t.Fatalf("request bytes changed\n got %x\nwant %x", got, want)
	}
	enc, err := proto.Marshal(WithYueConnTag(flow, ""))
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte{0x0a, 16}, XRV...); !bytes.Equal(enc, want) {
		t.Fatalf("flow addons changed: %x", enc)
	}
}

func TestYueConnTagOnIsReadableByUntaggedServers(t *testing.T) {
	const tag = "AbCdEf012_-"
	for _, base := range []*Addons{nil, {Flow: XRV}} {
		tagged := WithYueConnTag(base, tag)
		if base != nil && (base.ProtoReflect().GetUnknown() != nil) {
			t.Fatal("shared addons must not be mutated")
		}
		raw, err := proto.Marshal(tagged)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 255 {
			t.Fatalf("addons exceed the 1-byte length prefix: %d", len(raw))
		}
		// Xray-core and mihomo's sing_vless listener: proto.Unmarshal into
		// the same {Flow=1, Seed=2} schema. Unknown field -> ignored.
		var decoded Addons
		if err := proto.Unmarshal(raw, &decoded); err != nil {
			t.Fatalf("protobuf decode rejected the tagged addons: %v", err)
		}
		if decoded.Flow != tagged.Flow || decoded.Seed != nil {
			t.Fatalf("known fields changed: %+v", &decoded)
		}
		// mihomo's hand-written parser skips unknown LEN fields.
		hand, err := ReadAddons(raw)
		if err != nil || hand.Flow != tagged.Flow {
			t.Fatalf("ReadAddons: %v %+v", err, hand)
		}
		if got := YueConnTagOf(raw); got != tag {
			t.Fatalf("server-side extraction = %q", got)
		}
		// Only the tag was added: stripping it restores the untagged bytes.
		plain, _ := proto.Marshal(&Addons{Flow: tagged.Flow})
		if !bytes.HasPrefix(raw, plain) || len(raw) != len(plain)+2+1+len(tag) {
			t.Fatalf("unexpected encoding %x (plain %x)", raw, plain)
		}
	}
	// Full request: header carries the tagged addons, rest unchanged.
	payload := []byte("hello")
	tagged := WithYueConnTag(nil, tag)
	raw, _ := proto.Marshal(tagged)
	if got, want := requestBytes(t, tagged, payload), goldenRequest(raw, payload); !bytes.Equal(got, want) {
		t.Fatalf("tagged request\n got %x\nwant %x", got, want)
	}
}

func TestYueConnTagOfIgnoresOtherFields(t *testing.T) {
	raw, _ := proto.Marshal(&Addons{Flow: XRV, Seed: []byte{1, 2}})
	if YueConnTagOf(raw) != "" {
		t.Fatal("untagged addons reported a tag")
	}
	if YueConnTagOf([]byte{0xff}) != "" {
		t.Fatal("garbage reported a tag")
	}
}
