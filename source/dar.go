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

package dar

import (
	"archive/tar"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"qvm"
	"qvmd"
	"strconv"
	"strings"
)

type Rab []byte

func (rab Rab) ReadAt(p []byte, off int64) (n int, err error) {
	if len(p) > len(rab)-int(off) {
		return copy(p, rab[off:]), io.EOF
	}
	return copy(p, rab[off:int(off)+len(p)]), nil
}

func (rab *Rab) Write(p []byte) (n int, err error) {
	*rab = append(*rab, p...)
	return len(p), nil
}

type File struct {
	QvmFile      *qvm.File
	CommentsFile *CommentsFile
	SyscallsFile *SyscallsFile
}

type CommentsFile struct {
	Data []byte
}

type SyscallsFile struct {
	Data []byte
}

func NewFile(r io.Reader) (*File, error) {
	rdr := tar.NewReader(r)
	f := new(File)

	gotQVM, gotComments, gotSyscalls := false, false, false

L:
	for {
		hdr, err := rdr.Next()
		switch {
		case err == io.EOF:
			break L
		case err != nil:
			return nil, err
		case strings.HasSuffix(hdr.Name, ".qvm"):
			data, err := ioutil.ReadAll(rdr)
			if err != nil {
				return nil, err
			}
			f.QvmFile, err = qvm.NewFile(Rab(data))
			if err != nil {
				return nil, err
			}
			gotQVM = true
		case strings.HasSuffix(hdr.Name, "csv"):
			f.CommentsFile, err = NewCommentsFile(rdr)
			if err != nil {
				return nil, err
			}
			_, _, err = f.CommentsFile.Parse()
			if err != nil {
				return nil, fmt.Errorf("Malformed comments file: %s", err)
			}
			gotComments = true
		case strings.HasSuffix(hdr.Name, "asm"):
			f.SyscallsFile, err = NewSyscallsFile(rdr)
			if err != nil {
				return nil, err
			}
			_, err = f.SyscallsFile.Parse()
			if err != nil {
				return nil, fmt.Errorf("Malformed syscalls file: %s", err)
			}
			gotSyscalls = true
		default:
			return nil, fmt.Errorf("Malformed dar: Extra file %s in archive.", hdr.Name)
		}
	}
	if !gotQVM || !gotComments || !gotSyscalls {
		return nil, fmt.Errorf("Malformed dar: Missing QVM, comments, or syscalls file.")
	}
	return f, nil
}

func (f *File) WriteTo(w io.Writer) error {
	tw := tar.NewWriter(w)
	hdr := new(tar.Header)
	hdr.Name = "file.qvm"
	hdr.Size = 32
	if f.QvmFile.Header.Magic == qvm.VM_MAGIC_VER2 {
		hdr.Size += 4
	}
	hdr.Size += int64(f.QvmFile.Header.CodeLength + f.QvmFile.Header.DataLength + f.QvmFile.Header.LitLength)
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	buf := new(Rab)
	binary.Write(buf, binary.LittleEndian, &f.QvmFile.Header)
	if _, err := tw.Write([]byte(*buf)[0:32]); err != nil {
		return err
	}
	if f.QvmFile.Header.Magic == qvm.VM_MAGIC_VER2 {
		if _, err := tw.Write([]byte(*buf)[32:]); err != nil {
			return err
		}
	}

	if _, err := tw.Write(f.QvmFile.Code); err != nil {
		return err
	}
	if _, err := tw.Write(f.QvmFile.Data); err != nil {
		return err
	}
	if _, err := tw.Write(f.QvmFile.Lit); err != nil {
		return err
	}

	hdr.Name = "comments.csv"
	hdr.Size = int64(len(f.CommentsFile.Data))
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(f.CommentsFile.Data); err != nil {
		return err
	}

	hdr.Name = "syscalls.asm"
	hdr.Size = int64(len(f.SyscallsFile.Data))
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if _, err := tw.Write(f.SyscallsFile.Data); err != nil {
		return err
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	return nil
}

func NewCommentsFile(r io.Reader) (*CommentsFile, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	cf := &CommentsFile{data}
	_, _, err = cf.Parse()

	if err != nil {
		return nil, err
	}
	return cf, nil
}

func (cf *CommentsFile) Parse() (map[int]string, map[int]string, error) {
	lines := strings.SplitN(string(cf.Data), string([]byte{'\n'}), -1)
	comments, renames := make(map[int]string, 0), make(map[int]string, 0)
	for _, line := range lines {
		parts := strings.SplitN(line, ",", -1)
		switch parts[0] {
		case "name":
			if len(parts) < 3 {
				continue
			}
			procKey, err := strconv.ParseUint(parts[1], 0, 64)
			if err != nil {
				continue
			}
			renames[int(procKey)] = parts[2]
		case "comment":
			if len(parts) < 3 {
				continue
			}
			num, err := strconv.ParseUint(parts[1], 0, 64)
			if err != nil {
				continue
			}
			comments[int(num)] = strings.Join(parts[2:], ",")
		}
	}
	return comments, renames, nil
}

func (cf *CommentsFile) Write(comments, renames map[int]string) error {
	cf.Data = make([]byte, 0)
	for num, comment := range comments {
		cf.Data = append(cf.Data, []byte(fmt.Sprintf("comment,%d,%s\n", num, comment))...)
	}
	for num, name := range renames {
		cf.Data = append(cf.Data, []byte(fmt.Sprintf("name,%d,%s\n", num, name))...)
	}
	return nil
}

func NewSyscallsFile(r io.Reader) (*SyscallsFile, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	sc := &SyscallsFile{data}
	_, err = sc.Parse()

	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (sf *SyscallsFile) Parse() (map[int]qvmd.Syscall, error) {
	lines := strings.SplitN(string(sf.Data), string([]byte{'\n'}), -1)
	syscalls := make(map[int]qvmd.Syscall, 0)
	for _, line := range lines {
		var name string
		var val int
		if n, err := fmt.Sscanf(line, "equ %s %d", &name, &val); err != nil || n != 2 {
			continue
		}
		syscalls[val] = qvmd.Syscall{name, 0}
	}
	return syscalls, nil
}

func (sf *SyscallsFile) Write(syscalls map[int]qvmd.Syscall) error {
	sf.Data = make([]byte, 0)
	for num, sc := range syscalls {
		sf.Data = append(sf.Data, []byte(fmt.Sprintf("asm %s %d\n", num, sc.Name))...)
	}
	return nil
}
