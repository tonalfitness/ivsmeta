/*
	Start with ivsmeta.Read. It does the parsing and returns a list of ID3 blocks
	along with their presentation times. The ID3 tag values also seems to follow a format
	which is captured by the Value type.
*/
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
	"github.com/tonalfitness/ivsmeta/pes"
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

type MetaOptional struct {
	Error    error
	MetaInfo *MetaInfo
}

const IVSMetadataStreamType = 21 // PES metatdata

// Read takes a reader pointing to a ts file (or concatenated files like: cat *.ts).
// No internal buffering is used so that's up to the caller if required.
func Read(r io.Reader) ([]*MetaInfo, error) {
	infoChan := make(chan *MetaOptional, 100)
	ReadStream(r, infoChan)
	meta := []*MetaInfo{}
	for mo := range infoChan {
		if mo.Error != nil {
			if errors.Is(mo.Error, io.EOF) {
				return meta, nil
			}
			return meta, mo.Error
		}
		meta = append(meta, mo.MetaInfo)
	}
	return meta, nil
}

func getStreamPID(r io.Reader) (int, error) {
	pat, err := psi.ReadPAT(r)
	if err != nil {
		return 0, fmt.Errorf("failed ReadPAT: %w", err)
	}

	// Find the metadata stream PID from the program map
	var metadataPID int
	pmap := pat.ProgramMap()
	for _, pid := range pmap {
		pmt, err := psi.ReadPMT(r, pid)
		if err != nil {
			return 0, fmt.Errorf("failed ReadPMT: %w", err)
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
		return 0, errors.New("no metadata stream found")
	}
	return metadataPID, nil
}

// ReadStream will return infos on the given channel. This function returns immediatly.
// If MetaOptionals are not consumed from the channel, the underlying read will block
// so buffer appropriately to your needs. Execution stops on the first error returned
// in the MetaOptional and the channel will be closed. io.EOF is returned to signal end
// of the stream.
func ReadStream(r io.Reader, infoChan chan *MetaOptional) {
	go func() {
		metadataPID, err := getStreamPID(r)
		if err != nil {
			errInfoChan(err, infoChan)
			return
		}
		readPacketStream(r, metadataPID, infoChan)
	}()
}

func readPacketStream(r io.Reader, metadataPID int, infoChan chan *MetaOptional) {
	pkt := new(packet.Packet)
	pesAccumulator := &pes.PESAccumulator{}
	for {
		_, err := io.ReadFull(r, pkt[:])
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				errInfoChan(io.EOF, infoChan)
				return
			}
			errInfoChan(fmt.Errorf("failed packet read: %w", err), infoChan)
			return
		}
		if pkt.PID() == metadataPID {
			done, err := pesAccumulator.Write(pkt)
			if err != nil {
				errInfoChan(fmt.Errorf("failed accumulation, bailing: %w", err), infoChan)
				return
			}
			if done {
				mi, err := parseID3(pesAccumulator)
				if err != nil {
					errInfoChan(err, infoChan)
					return
				}
				infoChan <- &MetaOptional{
					MetaInfo: mi,
				}
				pesAccumulator = &pes.PESAccumulator{}
			}
		}
	}
}

func errInfoChan(err error, infoChan chan *MetaOptional) {
	infoChan <- &MetaOptional{
		Error: err,
	}
	close(infoChan)
}

func parseID3(pesAccumulator *pes.PESAccumulator) (*MetaInfo, error) {
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
