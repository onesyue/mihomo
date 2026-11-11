package net

import (
	"bytes"
	"io"
	"testing"

	"github.com/metacubex/sing/common/buf"
	sbufio "github.com/metacubex/sing/common/bufio"
)

func TestSingChunkReaderPreservesOrderAcrossBufferSizes(t *testing.T) {
	for _, firstSize := range []int{2, 4} {
		reader := sbufio.NewChunkReader(bytes.NewReader([]byte("abcdefgh")), 4)
		first := make([]byte, firstSize)
		if _, err := io.ReadFull(reader, first); err != nil {
			t.Fatal(err)
		}
		large := buf.NewSize(8)
		if err := reader.ReadBuffer(large); err != nil {
			large.Release()
			t.Fatal(err)
		}
		got := append(append([]byte(nil), first...), large.Bytes()...)
		large.Release()
		rest, err := io.ReadAll(reader)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, rest...)
		if string(got) != "abcdefgh" {
			t.Fatalf("first read size %d: bytes reordered or lost: %q", firstSize, got)
		}
	}
}
