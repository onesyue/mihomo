package quic

import (
	"fmt"
	"testing"

	"github.com/metacubex/quic-go/internal/handshake"
	"github.com/metacubex/quic-go/internal/protocol"
	"github.com/metacubex/quic-go/internal/qerr"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// Upstream quic-go/quic-go#5857: initial padding must account for the AEAD
// tag of the coalesced 1-RTT close, including on the minimum QUIC path.
func TestPackConnectionCloseCoalescedClient1RTT(t *testing.T) {
	for _, maxPacketSize := range []protocol.ByteCount{1200, protocol.MaxPacketBufferSize} {
		t.Run(fmt.Sprint(maxPacketSize), func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			tp := newTestPacketPacker(t, mockCtrl, protocol.PerspectiveClient)
			tp.sealingManager.EXPECT().GetInitialSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
			tp.sealingManager.EXPECT().GetHandshakeSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
			tp.sealingManager.EXPECT().Get0RTTSealer().Return(nil, handshake.ErrKeysDropped)
			tp.sealingManager.EXPECT().Get1RTTSealer().Return(newMockShortHeaderSealer(mockCtrl), nil)
			for i, encLevel := range []protocol.EncryptionLevel{protocol.EncryptionInitial, protocol.EncryptionHandshake, protocol.Encryption1RTT} {
				pn := protocol.PacketNumber(i + 1)
				tp.pnManager.EXPECT().PeekPacketNumber(encLevel).Return(pn, protocol.PacketNumberLen2)
				tp.pnManager.EXPECT().PopPacketNumber(encLevel).Return(pn)
			}
			p, err := tp.packer.PackApplicationClose(&qerr.ApplicationError{ErrorMessage: "connection closed"}, maxPacketSize, protocol.Version1)
			require.NoError(t, err)
			defer p.buffer.Release()
			require.Len(t, p.longHdrPackets, 2)
			require.NotNil(t, p.shortHdrPacket)
			require.Equal(t, maxPacketSize, p.buffer.Len())
		})
	}
}
