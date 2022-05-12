package main

/*
#include <stdint.h>
struct iovec {
	intptr_t iov_base;
	size_t iov_len;
};
*/
import "C"


import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
	"time"
	
	"github.com/pkg/errors"
)

const waitPidErrorMessage = "waitpid ret value: %d"

func waitPid(pid int) error {
	ret := waitpid(pid)
	if ret == pid {
		return nil
	}

	return errors.Errorf(waitPidErrorMessage, ret)
}


// If it's on 64-bit platform, `^uintptr(0)` will get a 64-bit number full of one.
// After shifting right for 63-bit, only 1 will be left. Than we got 8 here.
// If it's on 32-bit platform, After shifting nothing will be left. Than we got 4 here.
const ptrSize = 4 << uintptr(^uintptr(0)>>63)
var threadRetryLimit = 10

type TracedProgram struct {
	pid     int
	tids    []int
	backupCode []byte
	backupRegs *syscall.PtraceRegs
	Entries []Entry
}

type Entry struct {
	StartAddress uint64
	EndAddress   uint64
	Privilege    string
	PaddingSize  uint64
	Path         string
}

// ===============================================================


func (p *TracedProgram) Mmap(length uint64, fd uint64) (uint64, error) {
	return p.Syscall(syscall.SYS_MMAP, 0, length, syscall.PROT_READ|syscall.PROT_WRITE|syscall.PROT_EXEC, syscall.MAP_ANON|syscall.MAP_PRIVATE, fd, 0)
}

func (p *TracedProgram) Wait() error {
	return waitPid(p.pid)
}

func (p *TracedProgram) Step() error {
	err := syscall.PtraceSingleStep(p.pid)
	if err != nil {
		return errors.WithStack(err)
	}

	return p.Wait()
}

func alignBuffer(buffer []byte) []byte {
	if buffer == nil {
		return nil
	}

	alignedSize := (len(buffer) / ptrSize) * ptrSize
	if alignedSize < len(buffer) {
		alignedSize += ptrSize
	}
	clonedBuffer := make([]byte, alignedSize)
	copy(clonedBuffer, buffer)

	return clonedBuffer
}

func (p *TracedProgram) PtraceWriteSlice(addr uint64, buffer []byte) error {
	wroteSize := 0

	buffer = alignBuffer(buffer)

	for wroteSize+ptrSize <= len(buffer) {
		addr := uintptr(addr + uint64(wroteSize))
		data := buffer[wroteSize : wroteSize+ptrSize]

		_, err := syscall.PtracePokeData(p.pid, addr, data)
		if err != nil {
			err = errors.WithStack(err)
			return errors.WithMessagef(err, "write to addr %x with %+v failed", addr, data)
		}

		wroteSize += ptrSize
	}

	return nil
}

// JumpToFakeFunc writes jmp instruction to jump to fake function
func (p *TracedProgram) JumpToFakeFunc(originAddr uint64, targetAddr uint64) error {
	instructions := make([]byte, 16)

	// mov rax, targetAddr;
	// jmp rax ;
	instructions[0] = 0x48
	instructions[1] = 0xb8
	binary.LittleEndian.PutUint64(instructions[2:10], targetAddr)
	instructions[10] = 0xff
	instructions[11] = 0xe0

	return p.PtraceWriteSlice(originAddr, instructions)
}

func (p *TracedProgram) SetToFakeFunc(originAddr uint64, targetAddr uint64) error {
	instructions := make([]byte, 8)
	binary.LittleEndian.PutUint64(instructions, targetAddr)
	return p.PtraceWriteSlice(originAddr, instructions)
}

// Protect will backup regs and rip into fields
func (p *TracedProgram) Protect() error {
	err := syscall.PtraceGetRegs(p.pid, p.backupRegs)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = syscall.PtracePeekData(p.pid, uintptr(p.backupRegs.Rip), p.backupCode)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (p *TracedProgram) Syscall(number uint64, args ...uint64) (uint64, error) {
	// 保存所有的寄存器
	err := p.Protect()
	if err != nil {
		fmt.Println("protect")
		return 0, err
	}

	var regs syscall.PtraceRegs

	err = syscall.PtraceGetRegs(p.pid, &regs)
	if err != nil {
		fmt.Println("get regs")
		return 0, err
	}
	regs.Rax = number
	for index, arg := range args {
		// All these registers are hard coded for x86 platform
		if index == 0 {
			regs.Rdi = arg
		} else if index == 1 {
			regs.Rsi = arg
		} else if index == 2 {
			regs.Rdx = arg
		} else if index == 3 {
			regs.R10 = arg
		} else if index == 4 {
			regs.R8 = arg
		} else if index == 5 {
			regs.R9 = arg
		} else {
			return 0, errors.New("too many arguments for a syscall")
		}
	}
	err = syscall.PtraceSetRegs(p.pid, &regs)
	if err != nil {
		fmt.Println("set regs")
		return 0, err
	}

	ip := make([]byte, ptrSize)

	// We only support x86-64 platform now, so using hard coded `LittleEndian` here is ok.
	binary.LittleEndian.PutUint16(ip, 0x050f)
	_, err = syscall.PtracePokeData(p.pid, uintptr(p.backupRegs.Rip), ip)
	if err != nil {
		fmt.Println("set rip")
		return 0, err
	}

	err = p.Step()
	if err != nil {
		fmt.Println("one step")
		return 0, err
	}

	err = syscall.PtraceGetRegs(p.pid, &regs)
	if err != nil {
		fmt.Println("get regs2")
		return 0, err
	}

	return regs.Rax, p.Restore()
}

func (p *TracedProgram) Restore() error {
	err := syscall.PtraceSetRegs(p.pid, p.backupRegs)
	if err != nil {
		return errors.WithStack(err)
	}

	_, err = syscall.PtracePokeData(p.pid, uintptr(p.backupRegs.Rip), p.backupCode)
	if err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (p *TracedProgram) WriteSlice(addr uint64, buffer []byte) error {
	size := len(buffer)

	localIov := C.struct_iovec{
		iov_base: C.long(uintptr(unsafe.Pointer(&buffer[0]))),
		iov_len:  C.ulong(size),
	}

	remoteIov := C.struct_iovec{
		iov_base: C.long(addr),
		iov_len:  C.ulong(size),
	}

	// process_vm_writev syscall number is 311
	_, _, errno := syscall.Syscall6(311, uintptr(p.pid), uintptr(unsafe.Pointer(&localIov)), uintptr(1), uintptr(unsafe.Pointer(&remoteIov)), uintptr(1), uintptr(0))
	if errno != 0 {
		return errors.WithStack(errno)
	}
	// TODO: check size and warn

	return nil
}

func (p *TracedProgram) ReadSlice(addr uint64, size uint64) (*[]byte, error) {
	buffer := make([]byte, size)

	localIov := C.struct_iovec{
		iov_base: C.long(uintptr(unsafe.Pointer(&buffer[0]))),
		iov_len:  C.size_t(size),
	}

	remoteIov := C.struct_iovec{
		iov_base: C.long(addr),
		iov_len:  C.size_t(size),
	}

	// process_vm_readv syscall number is 310
	_, _, errno := syscall.Syscall6(310, uintptr(p.pid), uintptr(unsafe.Pointer(&localIov)), uintptr(1), uintptr(unsafe.Pointer(&remoteIov)), uintptr(1), uintptr(0))
	if errno != 0 {
		return nil, errors.WithStack(errno)
	}
	// TODO: check size and warn

	return &buffer, nil
}

// 把slice写入目标进程中的一个mmap地址中
func (p *TracedProgram) MmapSlice(slice []byte) (*Entry, error) {
	size := uint64(len(slice))

	fmt.Printf("before mmap %d\n", size)
	addr, err := p.Mmap(8192, 0)
	fmt.Printf("============addr : %#x ======== %d\n", addr, addr)
	time.Sleep(time.Duration(100)*time.Second)
	if err != nil {
		fmt.Println("error in mmap")
		return nil, errors.WithStack(err)
	}
	fmt.Printf("after mmap\n")

	err = p.WriteSlice(addr, slice)
	if err != nil {
		fmt.Printf("error in writeslice\n")
		return nil, errors.WithStack(err)
	}
	fmt.Printf("after WriteSlice\n")

	return &Entry{
		StartAddress: addr,
		EndAddress:   addr + size,
		Privilege:    "rwxp",
		PaddingSize:  0,
		Path:         "",
	}, nil
}

func (p *TracedProgram) GetLibBuffer(entry *Entry) (*[]byte, error) {
	if entry.PaddingSize > 0 {
		return nil, errors.New("entry with padding size is not supported")
	}

	size := entry.EndAddress - entry.StartAddress

	return p.ReadSlice(entry.StartAddress, size)
}

func (p *TracedProgram) FindSymbolInEntry(symbolName string, entry *Entry) (uint64, uint64, error) {
	libBuffer, err := p.GetLibBuffer(entry)
	if err != nil {
		return 0, 0, err
	}

	reader := bytes.NewReader(*libBuffer)
	vdsoElf, err := elf.NewFile(reader)
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}

	loadOffset := uint64(0)

	for _, prog := range vdsoElf.Progs {
		if prog.Type == elf.PT_LOAD {
			loadOffset = prog.Vaddr - prog.Off

			// break here is enough for vdso
			break
		}
	}

	symbols, err := vdsoElf.DynamicSymbols()
	if err != nil {
		return 0, 0, errors.WithStack(err)
	}
	for _, symbol := range symbols {
		if symbol.Name == symbolName {
			offset := symbol.Value

			return entry.StartAddress + (offset - loadOffset), symbol.Size, nil
		}
	}
	return 0, 0, errors.New("cannot find symbol")
}

// ========================================================

// Read parse /proc/[pid]/maps and return a list of entry
// The format of /proc/[pid]/maps can be found in `man proc`.
func ReadF(pid int) ([]Entry, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	lines := strings.Split(string(data), "\n")

	var entries []Entry
	for _, line := range lines {
		sections := strings.Split(line, " ")
		if len(sections) < 3 {
			continue
		}

		var path string

		if len(sections) > 5 {
			path = sections[len(sections)-1]
		}

		addresses := strings.Split(sections[0], "-")
		startAddress, err := strconv.ParseUint(addresses[0], 16, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		endAddresses, err := strconv.ParseUint(addresses[1], 16, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		privilege := sections[1]

		paddingSize, err := strconv.ParseUint(sections[2], 16, 64)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		entries = append(entries, Entry{
			startAddress,
			endAddresses,
			privilege,
			paddingSize,
			path,
		})
		fmt.Println(entries.backup())
	}

	return entries, nil
}

// ========================================================
func Trace(pid int) (*TracedProgram, error) {
	traceSuccess := false

	tidMap := make(map[int]bool)
	retryCount := make(map[int]int)
	for {
		threads, err := ioutil.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		if err != nil {
			return nil, errors.WithStack(err)
		}

		// judge whether `threads` is a subset of `tidMap`
		subset := true

		tids := make(map[int]bool)
		for _, thread := range threads {
			tid64, err := strconv.ParseInt(thread.Name(), 10, 32)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			tid := int(tid64)

			_, ok := tidMap[tid]
			if ok {
				tids[tid] = true
				continue
			}
			subset = false

			err = syscall.PtraceAttach(tid)
			if err != nil {
				_, ok := retryCount[tid]
				if !ok {
					retryCount[tid] = 1
				} else {
					retryCount[tid]++
				}
				if retryCount[tid] < threadRetryLimit {
					continue
				}

				if !strings.Contains(err.Error(), "no such process") {
					return nil, errors.WithStack(err)
				}
				continue
			}
			defer func() {
				if !traceSuccess {
					err = syscall.PtraceDetach(tid)
					if err != nil {
						if !strings.Contains(err.Error(), "no such process") {
							fmt.Println("detach failed")
						}
					}
				}
			}()

			err = waitPid(tid)
			if err != nil {
				return nil, errors.WithStack(err)
			}

			fmt.Println("attach successfully", "tid", tid)
			tids[tid] = true
			tidMap[tid] = true
		}

		if subset {
			tidMap = tids
			break
		}
	}

	var tids []int
	for key := range tidMap {
		tids = append(tids, key)
	}

	entries, err := ReadF(pid)
	if err != nil {
		return nil, err
	}

	program := &TracedProgram{
		pid:        pid,
		tids:       tids,
		Entries:    entries,
		backupRegs: &syscall.PtraceRegs{},
		backupCode: make([]byte, ptrSize),
	}

	traceSuccess = true

	return program, nil
}

func FindTargetEntry(program *TracedProgram, TargetEntryName string) (*Entry) {
	var targetEntry *Entry
	for index := range program.Entries {
		// reverse loop is faster
		e := program.Entries[len(program.Entries)-index-1]
		fmt.Printf("Target entry loop [%s]\n", e.Path)
		if e.Path == TargetEntryName {
			targetEntry = &e
			break
		}
	}
	if targetEntry == nil {
		fmt.Println("Not found targetEbrty")
		return nil
	}
	return targetEntry
}

func main() {
	pid := 45131
	WriteSkewFakeImage := "fake_write.o"
	WriteSymbolName := "write"
	gotSection = ".got"

	// step1: 在.text段中找到write相关的代码
	writeimage, err := LoadFakeImageFromEmbedFs(WriteSkewFakeImage, WriteSymbolName)

	program, err := Trace(pid)
	
	// step2: 查找名称为 gotSection 的段
	GOTEntry := FindTargetEntry(program, gotSection)

	// step3: 把fakefunc的代码段拷贝到目标地址空间里
	fakeEntry, err := program.MmapSlice(writeimage.content)
	if err != nil {
		fmt.Println(errors.Wrapf(err, "mmap fake image"))
		return
	}
	fmt.Println(fakeEntry)

	// step4: 获取GOTEntry中write相关的数据
	originAddr, size, err := program.FindSymbolInEntry(WriteSymbolName, GOTEntry)
	if err != nil {
		fmt.Printf("find origin %s in vdso\n", test1SymbolName)
		return
	}

	// step5: 读到这段地址初始的数据,用于后续恢复
	originFuncBytes, err := program.ReadSlice(originAddr, size)
	if err != nil {
		fmt.Println("ReadSlice failed")
		return
	}

	// step6: 把fakefunc在目标进程中mmap的地址放到GOTentry的地址上
	err = program.SetToFakeFunc(originAddr, fakeEntry.StartAddress)
	if err != nil {
		fmt.Println("rewrite fail, recover fail")
		return
	}

	time.Sleep(1000*time.Second)
	return
}