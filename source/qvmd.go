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

package qvmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"qvm"
	"strings"
)

const (
	OP_ENTER = 3
	OP_CALL  = 5
	OP_CONST = 8
	OP_LOCAL = 9
	OP_JUMP  = 10
)

var MnemonicTable = []string{
	"UNDEF", "IGNORE", "BREAK", "ENTER", "LEAVE", "CALL",
	"PUSH", "POP", "CONST", "LOCAL", "JUMP", "EQ",
	"NE", "LTI", "LEI", "GTI", "GEI", "LTU",
	"LEU", "GTU", "GEU", "EQF", "NEF", "LTF",
	"LEF", "GTF", "GEF", "LOAD1", "LOAD2", "LOAD4",
	"STORE1", "STORE2", "STORE4", "ARG", "BLOCK_COPY", "SEX8",
	"SEX16", "NEGI", "ADD", "SUB", "DIVI", "DIVU",
	"MODI", "MODU", "MULI", "MULU", "BAND", "BOR",
	"BXOR", "BCOM", "LSH", "RSHI", "RSHU", "NEGF",
	"ADDF", "SUBF", "DIVF", "MULF", "CVIF", "CVFI"}

var ArgTable = []int{
	0, 0, 0, 4, 4, 0,
	0, 0, 4, 4, 0, 4,
	4, 4, 4, 4, 4, 4,
	4, 4, 4, 4, 4, 4,
	4, 4, 4, 0, 0, 0,
	0, 0, 0, 1, 4, 0,
	0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0}

type Context struct {
	QvmFile  *qvm.File
	Insns    []Instruction
	Procs    map[int]*Procedure
	Strings  map[int]string
	Syscalls map[int]Syscall
}

type Instruction struct {
	Op, Offset int
	Arg        []byte
	Valid      bool
}

type Procedure struct {
	Name                                                       string
	StartInstruction, StartOffset, InstructionCount, FrameSize int
	Callers                                                    []*Procedure
	Callees                                                    []*Procedure
}

type Syscall struct {
	Name string
	Argc int
}

func NewContext(qvmFile *qvm.File, parseNow bool) (*Context, error) {
	ctx := new(Context)
	ctx.QvmFile = qvmFile
	if !parseNow {
		return ctx, nil
	}

	if err := ctx.ParseInstructions(); err != nil {
		return nil, err
	}
	if err := ctx.ParseProcedures(); err != nil {
		return nil, err
	}
	if err := ctx.ParseCodeXRefs(); err != nil {
		return nil, err
	}
	if err := ctx.ParseStrings(); err != nil {
		return nil, err
	}

	return ctx, nil
}

func (ctx *Context) ParseInstructions() error {
	ctx.Insns = make([]Instruction, 0)
	for i, off := 0, 0; i < int(ctx.QvmFile.Header.InstructionCount); i++ {
		op := ctx.QvmFile.Code[off]
		if int(op) >= len(MnemonicTable) {
			ctx.Insns = append(ctx.Insns, Instruction{int(op), off, nil, false})
			off++
			continue
		}
		switch ArgTable[op] {
		case 0:
			ctx.Insns = append(ctx.Insns, Instruction{int(op), off, nil, true})
		case 1:
			ctx.Insns = append(ctx.Insns, Instruction{int(op), off, []byte{ctx.QvmFile.Code[off+1]}, true})
		case 4:
			ctx.Insns = append(ctx.Insns, Instruction{int(op), off, []byte{ctx.QvmFile.Code[off+1], ctx.QvmFile.Code[off+2], ctx.QvmFile.Code[off+3], ctx.QvmFile.Code[off+4]}, true})
		}
		off += 1 + ArgTable[op]
	}
	return nil
}

func (ctx *Context) ParseProcedures() error {
	ctx.Procs = make(map[int]*Procedure, 0)
	lastIndex := 0
	for i, insn := range ctx.Insns {
		if insn.Op == OP_ENTER {
			tgtBuf := bytes.NewBuffer(insn.Arg)
			var frameSize uint32
			err := binary.Read(tgtBuf, binary.LittleEndian, &frameSize)
			if err != nil {
				return fmt.Errorf("Error parsing ENTER instruction at %d(0x%x): %s", i, int(ctx.QvmFile.Header.CodeOffset)+insn.Offset, err)
			}
			ctx.Procs[i] = &Procedure{fmt.Sprintf("sub_%08x", i), i, insn.Offset, 0, int(frameSize), nil, nil}
			ctx.Procs[lastIndex].InstructionCount = i - ctx.Procs[lastIndex].StartInstruction
			lastIndex = i
		}
	}
	ctx.Procs[lastIndex].InstructionCount = len(ctx.Insns) - ctx.Procs[lastIndex].StartInstruction
	return nil
}

func (ctx *Context) ParseCodeXRefs() error {
	for _, proc := range ctx.Procs {
		for i := proc.StartInstruction; i < proc.StartInstruction+proc.InstructionCount; i++ {
			if ctx.Insns[i].Op == OP_CONST && ctx.Insns[i+1].Op == OP_CALL {
				tgtBuf := bytes.NewBuffer(ctx.Insns[i].Arg)
				var target int32
				err := binary.Read(tgtBuf, binary.LittleEndian, &target)
				if err != nil {
					return fmt.Errorf("Error parsing COSNT instruction at %d(0x%x): %s", i, int(ctx.QvmFile.Header.CodeOffset)+ctx.Insns[i].Offset, err)
				}
				if target < 0 {
					continue
				}
				if tgtProc, exists := ctx.Procs[int(target)]; exists {
					found := false
					for _, caller := range tgtProc.Callers {
						if caller == proc {
							found = true
						}
					}
					if !found {
						tgtProc.Callers = append(tgtProc.Callers, proc)
						proc.Callees = append(proc.Callees, tgtProc)
					}
				}
			}
		}
	}
	return nil
}

func (ctx *Context) ParseStrings() error {
	Lit := ctx.QvmFile.Lit
	ctx.Strings = make(map[int]string, 0)
	gotString := false
	stringStart := 0
	for i := 0; i < len(Lit); i++ {
		if Lit[i] != 0 && !gotString {
			gotString = true
			stringStart = i
			continue
		}
		if Lit[i] == 0 && gotString {
			ctx.Strings[int(ctx.QvmFile.Header.DataLength)+stringStart] = strings.Replace(string(Lit[stringStart:i]), "\n", `\n`, -1)
			gotString = false
		}
	}
	return nil
}

func (insn Instruction) Mnemonic() string {
	if !insn.Valid {
		return fmt.Sprintf("Invalid opcode: %d", insn.Op)
	}
	return MnemonicTable[insn.Op]
}

func (insn Instruction) ArgLength() int {
	if !insn.Valid {
		return 0
	}
	return ArgTable[insn.Op]
}
