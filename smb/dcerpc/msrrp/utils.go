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
package msrrp

import (
	"bytes"
	"encoding/binary"
	"io"
	"unicode/utf16"

	"github.com/ericblavier/go-smb/msdtyp"
)

//Always nullTerminate NewUnicodeStrings

func fromUnicodeStrArray(buf []byte) (result []string, err error) {
	if len(buf) < 2 {
		return
	}
	var currentString []uint16
	for i := 0; i < len(buf); i += 2 {
		// Ensure we have enough bytes for a uint16
		if i+1 >= len(buf) {
			break
		}

		// Combine two bytes into a UTF-16LE character
		char := (uint16(buf[i+1]) << 8) | uint16(buf[i])

		// Check if this is a null terminator
		if char == 0 {
			// If we have characters, add the string to result
			if len(currentString) > 0 {
				result = append(result, string(utf16.Decode(currentString)))
				currentString = nil
			} else {
				// Double null terminator - end of list
				break
			}
		} else {
			// Add character to current string
			currentString = append(currentString, char)
		}
	}
	return
}

func readConformantVaryingString(r *bytes.Reader) (s string, err error) {
	// Read the Max count
	var maxCount uint32
	err = binary.Read(r, le, &maxCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	if maxCount == 0 {
		// If maxCount is zero, we've likely encountered a null ptr
		return
	}
	// Read the offset
	var offset uint32
	err = binary.Read(r, le, &offset)
	if err != nil {
		log.Errorln(err)
		return
	}
	// Read the Actual count
	var actualCount uint32
	err = binary.Read(r, le, &actualCount)
	if err != nil {
		log.Errorln(err)
		return
	}
	if offset > 0 {
		_, err = r.Seek(int64(offset)*2, io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	if actualCount > 0 {
		// Read the unicode string
		unc := make([]byte, actualCount*2)
		err = binary.Read(r, le, unc)
		if err != nil {
			log.Errorln(err)
			return
		}

		s, err = msdtyp.FromUnicodeString(unc)
		if err != nil {
			log.Errorln(err)
			return
		}
	}

	paddLen := 4 - ((offset*2 + actualCount*2) % 4)

	if paddLen != 4 {
		_, err = r.Seek(int64(paddLen), io.SeekCurrent)
		if err != nil {
			log.Errorln(err)
			return
		}
	}
	return
}

func readConformantVaryingStringPtr(r *bytes.Reader) (s string, err error) {
	// Skip ReferentId Ptr
	_, err = r.Seek(4, io.SeekCurrent)
	if err != nil {
		log.Errorln(err)
		return
	}
	return readConformantVaryingString(r)
}

/*
	Write a conformant and varying string to the output stream

NOTE that this is a bit different than the DCERPC implementation as empty
strings are not encoded as two null bytes.
Furthermore, the MaxLength from the RRPUnicodeStr should also be encoded here.
*/
func writeConformantVaryingString(w io.Writer, bo binary.ByteOrder, us *RRPUnicodeStr) (n int, err error) {
	offset, count, paddlen, buffer := msdtyp.NewUnicodeStr(us.S, true)
	err = binary.Write(w, bo, uint32(us.MaxLength)) // MaxCount
	if err != nil {
		return
	}
	n += 4
	if us.S == "" {
		// Since we won't encode an empty string will null bytes, set the
		// actual length to 0
		count = 0
	}
	err = binary.Write(w, bo, offset)
	if err != nil {
		return
	}
	n += 4
	err = binary.Write(w, bo, count)
	if err != nil {
		return
	}
	n += 4
	if us.S == "" {
		// Don't encode null bytes for empty string
		return
	}

	_, err = w.Write(buffer)
	if err != nil {
		return
	}
	n += len(buffer)
	padd := make([]byte, paddlen)
	_, err = w.Write(padd)
	if err != nil {
		return
	}
	n += paddlen
	return
}

// Write a ptr to a conformant and varying string to the output stream
func writeConformantVaryingStringPtr(w io.Writer, bo binary.ByteOrder, us *RRPUnicodeStr, refid *uint32) (n int, err error) {
	var n2 int

	// Should this be supported?
	//if us.S == "" {
	//	// Empty strings are represented as a NULL Ptr
	//	n, err = w.Write([]byte{0, 0, 0, 0})
	//	if err != nil {
	//		log.Errorln(err)
	//	}
	//	return
	//}
	if *refid != 0 {
		err = binary.Write(w, bo, *refid)
		if err != nil {
			return
		}
		n = 4
	}
	*refid++
	n2, err = writeConformantVaryingString(w, bo, us)
	n += n2
	return
}
