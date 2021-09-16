package ivsmeta

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Comcast/gots"
	"github.com/Comcast/gots/packet"
	"github.com/Comcast/gots/psi"
	"github.com/tonalfitness/easyid3"
)

// Value wraps ID3 track values that have a Prefix and then the
// actual Value separated by a NUL charater.
// If there is no Prefix, it will be the empty string
type Value struct {
	Prefix string
	Value  string
}

func (v *Value) String() string {
	return fmt.Sprintf("%s/%s", v.Prefix, v.Value)
}

// MetaInfo contains the ID3 MetaData
// plus the PTS (presentation timestamp)
type MetaInfo struct {
	PTS      uint64
	MetaData MetaDataMap
}

func (mi *MetaInfo) String() string {
	return fmt.Sprintf("%3.1f: %v", mi.PTSSeconds(), mi.MetaData)
}

func (mi *MetaInfo) PTSSeconds() float64 {
	return float64(mi.PTS) / gots.PtsClockRate
}

type MetaDataMap map[string]*Value

func (mdm MetaDataMap) String() string {
	sb := &strings.Builder{}
	sb.WriteString("{")
	for k, v := range mdm {
		sb.WriteString(" ")
		sb.WriteString(k)
		sb.WriteString(":")
		sb.WriteString(v.String())
	}
	sb.WriteString(" }")
	return sb.String()
}

const IVSMetadataStreamType = 21 // PES metatdata

func Read(r io.Reader) ([]*MetaInfo, error) {
	meta := []*MetaInfo{}
	pat, err := psi.ReadPAT(r)
	if err != nil {
		return meta, fmt.Errorf("failed ReadPAT: %w", err)
	}

	// Find the metadata stream PID from the program map
	var metadataPID int
	pmap := pat.ProgramMap()
	for _, pid := range pmap {
		pmt, err := psi.ReadPMT(r, pid)
		if err != nil {
			return meta, fmt.Errorf("failed ReadPMT: %w", err)
		}
		for _, es := range pmt.ElementaryStreams() {
			if es.StreamType() == IVSMetadataStreamType {
				metadataPID = es.ElementaryPid()
				break
			}
		}
		if metadataPID != 0 {
			break
		}
	}
	if metadataPID == 0 {
		return meta, errors.New("no metadata stream found")
	}
	return readPackets(r, metadataPID)
}

func readPackets(r io.Reader, metadataPID int) ([]*MetaInfo, error) {
	meta := []*MetaInfo{}
	pkt := new(packet.Packet)
	pesAccumulator := &PESAccumulator{}
	for {
		_, err := io.ReadFull(r, pkt[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return meta, nil
			}
			return meta, fmt.Errorf("failed packet read: %w", err)
		}
		if pkt.PID() == metadataPID {
			done, err := pesAccumulator.Write(pkt)
			if err != nil {
				return meta, fmt.Errorf("failed accumulation, bailing: %w", err)
			}
			if done {
				mi, err := parseID3(pesAccumulator)
				if err != nil {
					fmt.Printf("accdata: %#v", string(pesAccumulator.Data))
					return meta, err
				}
				meta = append(meta, mi)
				pesAccumulator = &PESAccumulator{}
			}
		}
	}
}

func parseID3(pesAccumulator *PESAccumulator) (*MetaInfo, error) {
	tags, err := easyid3.ReadID3(bytes.NewReader(pesAccumulator.Data))
	if err != nil {
		return nil, fmt.Errorf("failed ID3 parse: %w", err)
	}
	md := make(MetaDataMap, len(tags))
	for tag, v := range tags {
		md[tag] = parseValue(v)
	}
	return &MetaInfo{
		PTS:      pesAccumulator.PESHeader.PTS(),
		MetaData: md,
	}, nil
}

func parseValue(v string) *Value {
	split := strings.Split(v, "\x00")
	if len(split) == 2 {
		return &Value{
			Prefix: split[0],
			Value:  split[1],
		}
	}
	return &Value{
		Value: v,
	}
}
