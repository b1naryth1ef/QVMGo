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

package main

import (
	"bufio"
	"bytes"
	"dar"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"qvm"
	"qvmd"
	"sort"
	"strconv"
	"strings"
)

type Context struct {
	disCtx   *qvmd.Context
	dar      *dar.File
	comments map[int]string
	renames  map[int]string
}

func printHeader(f *qvm.File) {
	version := "unknown"
	switch f.Header.Magic {
	case qvm.VM_MAGIC_VER1:
		version = "Ver1"
	case qvm.VM_MAGIC_VER2:
		version = "Ver2"
	}
	fmt.Printf("            Magic: 0x%x[%s]\n", f.Header.Magic, version)
	fmt.Printf("Instruction Count: 0x%x\n", f.Header.InstructionCount)
	fmt.Printf("      Code Offset: 0x%x\n", f.Header.CodeOffset)
	fmt.Printf("      Code Length: 0x%x\n", f.Header.CodeLength)
	fmt.Printf("      Data Offset: 0x%x\n", f.Header.DataOffset)
	fmt.Printf("      Data Length: 0x%x\n", f.Header.DataLength)
	fmt.Printf("       Lit Length: 0x%x\n", f.Header.LitLength)
	fmt.Printf("       Bss Length: 0x%x\n", f.Header.BssLength)
	if f.Header.Magic == qvm.VM_MAGIC_VER2 {
		fmt.Printf("Jump Table Length: 0x%x\n", f.Header.JumpTableLength)
	}
}

func printInfo(ctx *Context, proc *qvmd.Procedure) {
	fmt.Printf("             Name: %s\n", proc.Name)
	fmt.Printf("Start Instruction: 0x%x\n", proc.StartInstruction)
	fmt.Printf("     Start Offset: 0x%x\n", proc.StartOffset)
	fmt.Printf("      File Offset: 0x%x\n", proc.StartOffset+int(ctx.dar.QvmFile.Header.CodeOffset))
	fmt.Printf("Instruction Count: 0x%x\n", proc.InstructionCount)
	fmt.Printf("       Frame Size: 0x%x\n", proc.FrameSize)
	fmt.Printf("Callees(%d):\n", len(proc.Callees))
	for _, calleeProc := range proc.Callees {
		fmt.Printf("\t%s\n", calleeProc.Name)
	}
	fmt.Printf("Callers(%d):\n", len(proc.Callers))
	for _, callerProc := range proc.Callers {
		fmt.Printf("\t%s\n", callerProc.Name)
	}
}

func disassemble(ctx *Context, proc *qvmd.Procedure) {
	for i := proc.StartInstruction; i < proc.StartInstruction+proc.InstructionCount; i++ {
		arg := ""
		info := ""
		comment := ""
		if cmnt, exists := ctx.comments[i]; exists {
			comment = fmt.Sprintf("; %s", cmnt)
		}
		switch {
		case !ctx.disCtx.Insns[i].Valid:
			break
		case ctx.disCtx.Insns[i].Op == qvmd.OP_CONST:
			dstBuf := bytes.NewBuffer(ctx.disCtx.Insns[i].Arg)
			var dst int32
			if err := binary.Read(dstBuf, binary.LittleEndian, &dst); err != nil {
				fmt.Println(err)
				continue
			}
			switch {
			case ctx.disCtx.Insns[i+1].Op == qvmd.OP_CALL:
				if dst < 0 {
					//Syscall...
					if sc, exists := ctx.disCtx.Syscalls[int(dst)]; exists {
						info = fmt.Sprintf("; %s(%d)", sc.Name, dst)
					} else {
						info = fmt.Sprintf("; Unknown syscall: %d", dst)
					}
				} else {
					//Code xref...
					if tgtProc, exists := ctx.disCtx.Procs[int(dst)]; exists {
						info = fmt.Sprintf("; %s", tgtProc.Name)
					} else {
						info = fmt.Sprintf("; Unknown instruction num %d", dst)
					}
				}
			case uint32(dst) >= ctx.dar.QvmFile.Header.DataLength && uint32(dst) < ctx.dar.QvmFile.Header.DataLength+ctx.dar.QvmFile.Header.LitLength:
				if str, exists := ctx.disCtx.Strings[int(uint32(dst))]; exists {
					info = fmt.Sprintf("; String: \"%s\"", str)
				} else {
					info = fmt.Sprintf("; Unknown string ref: 0x%x", dst)
				}
			}
		case ctx.disCtx.Insns[i].Op == qvmd.OP_LOCAL:
			tgtBuf := bytes.NewBuffer(ctx.disCtx.Insns[i].Arg)
			var tgt uint32
			if err := binary.Read(tgtBuf, binary.LittleEndian, &tgt); err != nil {
				fmt.Println(err)
				continue
			}
			if int(tgt) > proc.FrameSize {
				info = fmt.Sprintf("; arg_%d", (tgt-8-uint32(proc.FrameSize))/4)
			}
		}
		if !ctx.disCtx.Insns[i].Valid {
			fmt.Printf("<0x%08x>: Illegal Opcode: %d\n", i, ctx.disCtx.Insns[i].Op)
			continue
		}
		switch ctx.disCtx.Insns[i].ArgLength() {
		case 1:
			arg = fmt.Sprintf("0x%02x", ctx.disCtx.Insns[i].Arg[0])
		case 4:
			argBuf := bytes.NewBuffer(ctx.disCtx.Insns[i].Arg)
			var argNum uint32
			if err := binary.Read(argBuf, binary.LittleEndian, &argNum); err != nil {
				fmt.Println(err)
				break
			}
			arg = fmt.Sprintf("0x%08x", argNum)
		}

		fmt.Printf("<0x%08x>: %-10s %10s %s%s\n", i, ctx.disCtx.Insns[i].Mnemonic(), arg, info, comment)
	}
}

func exitErrNotNil(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func main() {
	cfFile, scFile := "", ""
	flag.StringVar(&cfFile, "comments", "", "Specify a file containing comments and data references")
	flag.StringVar(&scFile, "syscalls", "", "Specify a file defining the syscalls")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Must specify at least one QVM or disassembly archive!")
		os.Exit(-1)
	}

	f, err := os.OpenFile(flag.Arg(0), os.O_RDWR, 0600)
	exitErrNotNil(err)

	ctx := new(Context)
	ctx.dar = new(dar.File)
	ctx.dar.CommentsFile = new(dar.CommentsFile)
	ctx.dar.SyscallsFile = new(dar.SyscallsFile)

	switch {
	case strings.HasSuffix(flag.Arg(0), ".qvm"):
		ctx.dar.QvmFile, err = qvm.NewFile(f)
		exitErrNotNil(err)
	case strings.HasSuffix(flag.Arg(0), ".dar"):
		ctx.dar, err = dar.NewFile(f)
		exitErrNotNil(err)
	default:
		fmt.Println("File needs to have a .qvm or .dar extension.")
		os.Exit(-1)
	}

	err = f.Close()
	exitErrNotNil(err)
	ctx.disCtx, err = qvmd.NewContext(ctx.dar.QvmFile, true)
	exitErrNotNil(err)
	ctx.comments, ctx.renames, err = ctx.dar.CommentsFile.Parse()
	exitErrNotNil(err)
	ctx.disCtx.Syscalls, err = ctx.dar.SyscallsFile.Parse()
	exitErrNotNil(err)

	if cfFile != "" {
		commentsFile, err := os.OpenFile(cfFile, os.O_RDWR, 0600)
		exitErrNotNil(err)
		ctx.dar.CommentsFile, err = dar.NewCommentsFile(commentsFile)
		exitErrNotNil(err)
		ctx.comments, ctx.renames, err = ctx.dar.CommentsFile.Parse()
		exitErrNotNil(err)
		err = commentsFile.Close()
		exitErrNotNil(err)
	}

	if scFile != "" {
		syscallsFile, err := os.OpenFile(scFile, os.O_RDWR, 0600)
		exitErrNotNil(err)
		ctx.dar.SyscallsFile, err = dar.NewSyscallsFile(syscallsFile)
		exitErrNotNil(err)
		ctx.disCtx.Syscalls, err = ctx.dar.SyscallsFile.Parse()
		exitErrNotNil(err)
		err = syscallsFile.Close()
		exitErrNotNil(err)
	}

	for num, rename := range ctx.renames {
		if _, exists := ctx.disCtx.Procs[num]; exists {
			ctx.disCtx.Procs[num].Name = rename
		}
	}

	stdin := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("qvmd> ")
		input, err := stdin.ReadString(byte('\n'))
		exitErrNotNil(err)
		cmd := strings.SplitN(strings.TrimSpace(input), " ", -1)
		if strings.ToLower(cmd[0]) == "quit" || err == io.EOF {
			fmt.Print("\n")
			os.Exit(0)
		}

		switch cmd[0] {
		case "help":
			fmt.Println("                   comments - Print all comments")
			fmt.Println("comment <insnNum> <comment> - Assign a comment to instruction number <insnNum>")
			fmt.Println(" dis[as[semble]] <funcName> - Disassemble function <funcName>")
			fmt.Println("             disi <insnNum> - Disassemble function containing instruction <insnNum>")
			fmt.Println("                     header - Print the header for the QVM file")
			fmt.Println("            info <funcName> - Print information about function <funcName>")
			fmt.Println("            infoi <insnNum> - Print information about function containing instruction <insnNum>")
			fmt.Println("      ren[ame] <orig> <new> - Rename function <orig> to <new>")
			fmt.Println("              save [tgtDar] - Save your disassembly. If opened as a QVM [tgtDar] is required")
			fmt.Println("      savecomments [tgtCsv] - Save all comments and renamed functions")
			fmt.Println("      savesyscalls [tgtAsm] - Save all syscalls")
			fmt.Println("              sref <string> - Search for functions referencing strings containing <string>")
			fmt.Println("                   syscalls - Print all known syscalls")

		case "comments":
			for num, comment := range ctx.comments {
				fmt.Printf("0x%08x: %s\n", num, comment)
			}
		case "comment":
			if len(cmd) < 3 {
				fmt.Println("Usage: comment <insnNum> <comment>")
				break
			}
			insn, err := strconv.ParseUint(cmd[1], 0, 64)
			if err != nil {
				fmt.Println("Usage: comment <insnNum> <comment>")
				break
			}
			goAhead := true
			if _, exists := ctx.comments[int(insn)]; exists {
				fmt.Print("Overwrite existing comment? [Y/n]: ")
			Ans1:
				for {
					answer, err := stdin.ReadString(byte('\n'))
					if err != nil {
						fmt.Println(err)
						break
					}
					answer = strings.ToLower(strings.TrimSpace(answer))
					switch answer {
					case "n", "no":
						goAhead = false
						break Ans1
					case "y", "yes", "":
						break Ans1
					default:
						fmt.Print("Please answer \"yes\" or \"no\": ")
					}
				}
			}
			if goAhead {
				ctx.comments[int(insn)] = strings.Join(cmd[2:], " ")
			} else {
				fmt.Println("Comment not replaced.")
			}
		case "dis", "disas", "disassemble":
			if len(cmd) < 2 {
				fmt.Printf("Usage: %s <funcName>\n", cmd[0])
				break
			}
			found := false
			for _, proc := range ctx.disCtx.Procs {
				if proc.Name == cmd[1] {
					disassemble(ctx, proc)
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("No function named \"%s\" found.\n", cmd[1])
			}
		case "disi":
			if len(cmd) < 2 {
				fmt.Println("Usage: disi <insnNum>")
				break
			}
			tgt, err := strconv.ParseUint(cmd[1], 0, 64)
			if err != nil {
				fmt.Println(err)
				break
			}
			found := false
			for _, proc := range ctx.disCtx.Procs {
				if int(tgt) >= proc.StartInstruction && int(tgt) < proc.StartInstruction+proc.InstructionCount {
					disassemble(ctx, proc)
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("No function containing instruction %d\n", tgt)
			}
		case "header":
			printHeader(ctx.dar.QvmFile)
		case "info":
			if len(cmd) < 2 {
				fmt.Println("Usage: info <funcName>")
				break
			}
			found := false
			for _, proc := range ctx.disCtx.Procs {
				if proc.Name == cmd[1] {
					printInfo(ctx, proc)
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("No function named \"%s\" found.\n", cmd[1])
			}
		case "infoi":
			if len(cmd) < 2 {
				fmt.Println("Usage: infoi <insnNum>")
				break
			}
			tgt, err := strconv.ParseUint(cmd[1], 0, 64)
			if err != nil {
				fmt.Println(err)
				break
			}
			found := false
			for _, proc := range ctx.disCtx.Procs {
				if int(tgt) >= proc.StartInstruction && int(tgt) < proc.StartInstruction+proc.InstructionCount {
					printInfo(ctx, proc)
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("No function containing instruction %d\n", tgt)
			}
		case "ren", "rename":
			if len(cmd) < 3 {
				fmt.Printf("Usage: %s <orig> <new>\n", cmd[0])
				break
			}
			found := false
			for _, proc := range ctx.disCtx.Procs {
				if proc.Name == cmd[1] {
					proc.Name = cmd[2]
					found = true
					ctx.renames[proc.StartInstruction] = cmd[2]
				}
			}
			if !found {
				fmt.Printf("No function named \"%s\" found.\n", cmd[1])
			}
		case "save":
			tgtFile := flag.Arg(0)
			if len(cmd) >= 2 {
				tgtFile = strings.Join(cmd[1:], " ")
			}
			if strings.HasSuffix(tgtFile, ".qvm") {
				fmt.Println("Opened as a single QVM. Please save to a new dar")
				break
			}
			if err := ctx.dar.CommentsFile.Write(ctx.comments, ctx.renames); err != nil {
				fmt.Println(err)
				break
			}

			f, err = os.OpenFile(tgtFile, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				fmt.Println(err)
			}
			err = f.Truncate(0)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			_, err = f.Seek(0, 0)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			err = ctx.dar.WriteTo(f)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			err = f.Sync()
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			err = f.Close()
			if err != nil {
				fmt.Println(err)
			}

		case "savecomments":
			tgtFile := cfFile
			if len(cmd) >= 2 {
				tgtFile = strings.Join(cmd[1:], " ")
			}
			if tgtFile == "" {
				fmt.Println("Usage: savecomments <file>")
				break
			}

			if err := ctx.dar.CommentsFile.Write(ctx.comments, ctx.renames); err != nil {
				fmt.Println(err)
				break
			}

			f, err := os.OpenFile(tgtFile, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				fmt.Println(err)
				break
			}

			err = f.Truncate(0)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			_, err = f.Seek(0, 0)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			if n, err := f.Write(ctx.dar.CommentsFile.Data); err != nil || n != len(ctx.dar.CommentsFile.Data) {
				fmt.Printf("Error writing comments: %s\n", err)
				f.Close()
				break
			}
			err = f.Close()
			if err != nil {
				fmt.Println(err)
			}

		case "savesyscalls":
			tgtFile := scFile
			if len(cmd) >= 2 {
				tgtFile = strings.Join(cmd[1:], " ")
			}

			if tgtFile == "" {
				fmt.Println("savesyscalls <file>")
				break
			}

			f, err := os.OpenFile(tgtFile, os.O_RDWR|os.O_CREATE, 0600)
			if err != nil {
				fmt.Println(err)
				break
			}

			err = f.Truncate(0)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			_, err = f.Seek(0, 0)
			if err != nil {
				fmt.Println(err)
				f.Close()
				break
			}
			if n, err := f.Write(ctx.dar.SyscallsFile.Data); err != nil || n != len(ctx.dar.SyscallsFile.Data) {
				fmt.Printf("Error writing syscalls: %s\n", err)
				f.Close()
				break
			}
			err = f.Close()
			if err != nil {
				fmt.Println(err)
			}
		case "sref":
			if len(cmd) < 2 {
				fmt.Println("Usage: sref <string>")
			}
			found := false
			for _, proc := range ctx.disCtx.Procs {
				for i := proc.StartInstruction; i < proc.StartInstruction+proc.InstructionCount; i++ {
					if ctx.disCtx.Insns[i].Op == qvmd.OP_CONST && ctx.disCtx.Insns[i+1].Op != qvmd.OP_CALL {
						tgtBuf := bytes.NewBuffer(ctx.disCtx.Insns[i].Arg)
						var tgt uint32
						if err := binary.Read(tgtBuf, binary.LittleEndian, &tgt); err != nil {
							fmt.Println(err)
						}
						if tgt >= ctx.dar.QvmFile.Header.DataLength && tgt < ctx.dar.QvmFile.Header.DataLength+ctx.dar.QvmFile.Header.LitLength {
							if str, exists := ctx.disCtx.Strings[int(tgt)]; exists {
								if strings.Contains(str, strings.Join(cmd[1:], " ")) {
									fmt.Println(proc.Name)
									found = true
								}
							}
						}
					}
				}
			}
			if !found {
				fmt.Printf("No functions containing \"%s\"\n", strings.Join(cmd[1:], " "))
			}
		case "syscalls":
			keys := make([]int, len(ctx.disCtx.Syscalls))
			for key, _ := range ctx.disCtx.Syscalls {
				keys = append(keys, key)
			}
			sort.Sort(sort.IntSlice(keys))
			for _, key := range keys {
				fmt.Printf("%d: %s\n", key, ctx.disCtx.Syscalls[key].Name)
			}
		}
	}
}
