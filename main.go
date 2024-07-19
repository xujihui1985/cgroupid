package main

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	errEAGAIN error = syscall.EAGAIN
	errEINVAL error = syscall.EINVAL
	errENOENT error = syscall.ENOENT
)

func main() {
	cg := os.Args[1]
	_, err := GetCgroupID(cg)
	if err != nil {
		panic(err)
	}
}

func GetCgroupID(pathname string) (uint64, error) {
	var (
		stat syscall.Statfs_t
		cgid uint64
		err  error
	)
	if err = syscall.Statfs(pathname, &stat); err != nil {
		return 0, err
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC && stat.Type != unix.CGROUP_SUPER_MAGIC {
		return 0, errors.New("invalid cgroup type")
	}
	if cgid, err = getCgroupID(pathname); err != nil {
		return 0, err
	}
	return cgid, nil
}

func getCgroupID(path string) (uint64, error) {
	var _mid int32
	// Try first with a small buffer, assuming the handle will
	// only be 32 bytes.
	size := uint32(8 + unsafe.Sizeof(fileHandle{}))
	didResize := false
	for {
		buf := make([]byte, size)
		fh := (*fileHandle)(unsafe.Pointer(&buf[0]))
		fh.Bytes = size - uint32(unsafe.Sizeof(fileHandle{}))
		err := nameToHandleAt(unix.AT_FDCWD, path, fh, &_mid, 0)
		if errors.Is(err, unix.EOVERFLOW) {
			if didResize {
				// We shouldn't need to resize more than once
				return 0, err
			}
			didResize = true
			size = fh.Bytes + uint32(unsafe.Sizeof(fileHandle{}))
			continue
		}
		if err != nil {
			return 0, err
		}
		return fh.cgid, nil
	}
}

type fileHandle struct {
	Bytes uint32
	Type  int32
	cgid  uint64
}

func nameToHandleAt(dirFD int, pathname string, fh *fileHandle, mountID *int32, flags int) (err error) {
	var _p0 *byte
	_p0, err = unix.BytePtrFromString(pathname)
	if err != nil {
		return
	}
	_, _, e1 := unix.Syscall6(unix.SYS_NAME_TO_HANDLE_AT, uintptr(dirFD), uintptr(unsafe.Pointer(_p0)), uintptr(unsafe.Pointer(fh)), uintptr(unsafe.Pointer(mountID)), uintptr(flags), 0)
	if e1 != 0 {
		err = errnoErr(e1)
	}
	return
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case unix.EAGAIN:
		return errEAGAIN
	case unix.EINVAL:
		return errEINVAL
	case unix.ENOENT:
		return errENOENT
	}
	return e
}
