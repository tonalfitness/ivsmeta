package ivsmeta

import (
	"fmt"

	"github.com/Comcast/gots/packet"
)

/*
 * PESAccumulator accumulates packets starting from a PES packet
 * up until the size specified by the PES Header
 */
type PESAccumulator struct {
	PESHeader  *PESHeader
	packetSize int
	Data       []byte
}

func (pa *PESAccumulator) Write(pkt *packet.Packet) (done bool, err error) {
	if pa.PESHeader == nil {
		pesBytes, err := packet.PESHeader(pkt)
		if err != nil {
			return false, fmt.Errorf("first packet must contain a PES Header: %w", err)
		}
		pa.PESHeader, err = NewPESHeader(pesBytes)
		if err != nil {
			return false, fmt.Errorf("failed PES parse: %w", err)
		}
		pa.Data = make([]byte, len(pa.PESHeader.Data()))
		copy(pa.Data, pa.PESHeader.Data())
		pa.packetSize = pa.PESHeader.PacketSize()
		return pa.checkDone()
	}

	payload, err := pkt.Payload()
	if err != nil {
		return false, fmt.Errorf("failed getting payload: %w", err)
	}
	pa.Data = append(pa.Data, payload...)
	return pa.checkDone()

}

func (pa *PESAccumulator) checkDone() (bool, error) {
	if len(pa.Data) > pa.packetSize {
		return true, fmt.Errorf("overrun; expected %d got %d", pa.packetSize, len(pa.Data))
	}
	return len(pa.Data) == pa.PESHeader.PacketSize(), nil
}
