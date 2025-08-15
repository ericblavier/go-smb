// MIT License
//
// # Copyright (c) 2023 Jimmy Fjällid
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/ericblavier/go-smb/smb/encoder"
)

const (
	SMB1CommandNegotiate byte = 0x72
)

// MS-CIFS 2.2.3.1 SMB Header
type SMB1Header struct { // 32 bytes
	Protocol         []byte `smb:"fixed:4"` // Must contain 0xff, S, M, B
	Command          uint8
	Status           uint32
	Flags            uint8
	Flags2           uint16
	PIDHigh          uint16
	SecurityFeatures []byte `smb:"fixed:8"`
	Reserved         uint16
	TID              uint16
	PIDLow           uint16
	UID              uint16
	MID              uint16
}

type SMB1Dialect struct {
	BufferFormat  uint8  // Must be 0x2
	DialectString string // Null-terminated string
}

type SMB1NegotiateReq struct {
	Header    SMB1Header
	WordCount uint8
	ByteCount uint16
	Dialects  []SMB1Dialect
}

func (self *SMB1NegotiateReq) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	log.Debugln("In MarshalBinary for SMB1NegotiateReq")
	buf := make([]byte, 0, 46)
	w := bytes.NewBuffer(buf)
	hBuf, err := encoder.Marshal(self.Header)
	if err != nil {
		log.Debugln(err)
		return nil, err
	}

	w.Write(hBuf)

	// WordCount
	w.WriteByte(self.WordCount)

	dialectsBuffer := make([]byte, 0, 11)
	for _, item := range self.Dialects {
		dialectsBuffer = append(dialectsBuffer, 0x2)
		dialectsBuffer = append(dialectsBuffer, []byte(item.DialectString)...)
	}
	// ByteCount
	binary.Write(w, binary.LittleEndian, uint16(len(dialectsBuffer)))

	// Dialects
	binary.Write(w, binary.LittleEndian, dialectsBuffer)

	return w.Bytes(), nil
}

func (self *SMB1NegotiateReq) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	return fmt.Errorf("NOT IMPLEMENTED UnmarshalBinary for SMB1NegotiateReq")
}

// MS-CIFS 2.2.4.52.2 SMB_COM_NEGOTIATE Response
type SMB1NegotiateRes struct {
	Header       SMB1Header
	WordCount    uint8
	DialectIndex uint16 // Index of selected dialect, 0xFFFF if no dialect acceptable
	SecurityMode uint8  // Security mode flags
	MaxMpxCount  uint16 // Maximum pending multiplexed requests
	MaxVcCount   uint16 // Maximum VCs between client and server
	MaxBufSize   uint32 // Maximum transmit buffer size
	MaxRawSize   uint32 // Maximum raw buffer size
	SessionKey   uint32 // Unique token identifying session
	Capabilities uint32 // Server capabilities
	SystemTime   uint64 // Server time (FILETIME)
	TimeZone     int16  // Server time zone (minutes from UTC)
	KeyLength    uint8  // Security blob length
	ByteCount    uint16 // Count of data bytes
	SecurityBlob []byte // Security blob (NTLM challenge, etc.)
}

func (self *SMB1NegotiateRes) UnmarshalBinary(buf []byte, meta *encoder.Metadata) error {
	if len(buf) < 37 { // Minimum size: 32 byte header + 5 bytes minimum response
		return fmt.Errorf("SMB1 negotiate response too short: %d bytes", len(buf))
	}

	// Parse header
	if err := encoder.Unmarshal(buf[:32], &self.Header); err != nil {
		return fmt.Errorf("failed to unmarshal SMB1 header: %v", err)
	}

	// Parse negotiate response body
	offset := 32
	self.WordCount = buf[offset]
	offset++

	if self.WordCount == 0 {
		// No common dialect found
		self.DialectIndex = 0xFFFF
		return nil
	}

	// Parse DialectIndex (required field)
	if len(buf) < offset+2 {
		return fmt.Errorf("SMB1 negotiate response missing DialectIndex")
	}
	self.DialectIndex = binary.LittleEndian.Uint16(buf[offset : offset+2])
	offset += 2

	// Parse remaining fields with bounds checking - some servers send shorter responses
	if len(buf) >= offset+1 {
		self.SecurityMode = buf[offset]
		offset++
	}

	if len(buf) >= offset+2 {
		self.MaxMpxCount = binary.LittleEndian.Uint16(buf[offset : offset+2])
		offset += 2
	}

	if len(buf) >= offset+2 {
		self.MaxVcCount = binary.LittleEndian.Uint16(buf[offset : offset+2])
		offset += 2
	}

	if len(buf) >= offset+4 {
		self.MaxBufSize = binary.LittleEndian.Uint32(buf[offset : offset+4])
		offset += 4
	}

	if len(buf) >= offset+4 {
		self.MaxRawSize = binary.LittleEndian.Uint32(buf[offset : offset+4])
		offset += 4
	}

	if len(buf) >= offset+4 {
		self.SessionKey = binary.LittleEndian.Uint32(buf[offset : offset+4])
		offset += 4
	}

	if len(buf) >= offset+4 {
		self.Capabilities = binary.LittleEndian.Uint32(buf[offset : offset+4])
		offset += 4
	}

	if len(buf) >= offset+8 {
		self.SystemTime = binary.LittleEndian.Uint64(buf[offset : offset+8])
		offset += 8
	}

	if len(buf) >= offset+2 {
		self.TimeZone = int16(binary.LittleEndian.Uint16(buf[offset : offset+2]))
		offset += 2
	}

	if len(buf) >= offset+1 {
		self.KeyLength = buf[offset]
		offset++
	}

	// Parse ByteCount and SecurityBlob
	if len(buf) >= offset+2 {
		self.ByteCount = binary.LittleEndian.Uint16(buf[offset : offset+2])
		offset += 2

		if self.KeyLength > 0 && len(buf) >= offset+int(self.KeyLength) {
			self.SecurityBlob = make([]byte, self.KeyLength)
			copy(self.SecurityBlob, buf[offset:offset+int(self.KeyLength)])
		}
	}

	return nil
}

func (self *SMB1NegotiateRes) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return nil, fmt.Errorf("NOT IMPLEMENTED MarshalBinary for SMB1NegotiateRes")
}

func (s *Session) NewSMB1NegotiateReq() (req SMB1NegotiateReq, err error) {
	header := SMB1Header{
		Protocol:         []byte(ProtocolSmb),
		Command:          SMB1CommandNegotiate,
		Flags:            0x18,   // Canonicalized Pathnames, Case sensitivity (path names are caseless)
		Flags2:           0xc801, // Unicode strings, NT Error codes, Extended security negotiation, Long names are allowed
		SecurityFeatures: make([]byte, 8),
		TID:              0xffff,
	}

	// Dialects ordered in increasing preference (SMBv1 first, then SMBv2)
	dialects := []SMB1Dialect{
		// Traditional SMBv1 dialects for compatibility
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("PC NETWORK PROGRAM 1.0\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("LANMAN1.0\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("Windows for Workgroups 3.1a\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("LM1.2X002\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("LANMAN2.1\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("NT LM 0.12\x00"),
		},
		// SMBv2 dialects (higher preference)
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("SMB 2.002\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("SMB 2.100\x00"),
		},
		SMB1Dialect{
			BufferFormat:  0x2,
			DialectString: string("SMB 2.???\x00"),
		},
	}

	req = SMB1NegotiateReq{
		Header:   header,
		Dialects: dialects,
	}

	return
}
