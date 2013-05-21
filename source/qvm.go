/*
            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                    Version 2, December 2004

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

 Everyone is permitted to copy and distribute verbatim or modified
 copies of this license document, and changing it is allowed as long
 as the name is changed.

            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

  0. You just DO WHAT THE FUCK YOU WANT TO.
*/

package qvm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	VM_MAGIC_VER1 = 0x12721444
	VM_MAGIC_VER2 = 0x12721445
)

//Header represents the header for a QVMFile. Note that even if VM_MAGIC_VER1
//Header still contains a JumpTableLength field.
type Header struct {
	Magic            uint32
	InstructionCount uint32
	CodeOffset       uint32
	CodeLength       uint32
	DataOffset       uint32
	DataLength       uint32
	LitLength        uint32
	BssLength        uint32
	JumpTableLength  uint32
}

//Pretty simple, File has a header and the three sections normally embedded
//in a QVM file.
type File struct {
	Header Header
	Code   []byte
	Data   []byte
	Lit    []byte
}

//Also simple. Takes an io.Reader and creates a File from it.
//Also performs a few sanity checks to save the programmer from
//extra work and potentially malicious files.
func NewFile(r io.ReaderAt) (*File, error) {

	//Read the header...
	f := &File{Header{}, nil, nil, nil}
	hdr := make([]byte, 36)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, err
	}

	hdrBuf := bytes.NewBuffer(hdr)
	if err := binary.Read(hdrBuf, binary.LittleEndian, &f.Header); err != nil {
		return nil, err
	}

	//Run a couple sanity checks on the header...
	//First case: Unrecognized magic number
	if f.Header.Magic != VM_MAGIC_VER1 && f.Header.Magic != VM_MAGIC_VER2 {
		return nil, fmt.Errorf("Unrecognized QVM version[Magic: 0x%08x]", f.Header.Magic)
	}

	//Second case: Magic is VM_MAGIC_VER1 but CodeOffset != 32
	if f.Header.Magic == VM_MAGIC_VER1 && f.Header.CodeOffset != 32 {
		return nil, fmt.Errorf("Invalid code offset[%d] for magic(Ver1)[0x%08x]", f.Header.CodeOffset, f.Header.Magic)
	}

	//Third case: Magic is VM_MAGIC_VER2 but CodeOffset != 36
	if f.Header.Magic == VM_MAGIC_VER2 && f.Header.CodeOffset != 36 {
		return nil, fmt.Errorf("Invalid code offset[%d] for magic(Ver2)[0x%08x]", f.Header.CodeOffset, f.Header.Magic)
	}

	//Fourth case: CodeOffset + CodeLength + (CodeLength % 4) != DataOffset
	if f.Header.CodeOffset+f.Header.CodeLength+(f.Header.CodeLength%4) != f.Header.DataOffset {
		return nil, fmt.Errorf("Invalid data offset[0x%x] or code length[0x%x]", f.Header.DataOffset, f.Header.CodeLength)
	}

	//Fifth case: CodeLength < InstructionCount(Need at least 1 byte for each instruction...)
	if f.Header.CodeLength < f.Header.InstructionCount {
		return nil, fmt.Errorf("Code length[%d] < instruction count[%d]", f.Header.CodeLength, f.Header.InstructionCount)
	}

	//Read the Code/Data/Lit sections...
	f.Code = make([]byte, f.Header.CodeLength)
	if _, err := r.ReadAt(f.Code, int64(f.Header.CodeOffset)); err != nil {
		return nil, err
	}

	f.Data = make([]byte, f.Header.DataLength)
	if _, err := r.ReadAt(f.Data, int64(f.Header.DataOffset)); err != nil {
		return nil, err
	}

	f.Lit = make([]byte, f.Header.LitLength)
	if _, err := r.ReadAt(f.Lit, int64(f.Header.DataOffset+f.Header.DataLength)); err != nil {
		return nil, err
	}

	return f, nil
}
