// Go frontend fixture with the static_fixture.c protocol: a package-level
// value, a pointer to it and a non-inlined writer; stdin 'b' runs the writer,
// 'r' reads the value, 's'/'x' start/stop a busy goroutine, 'q' exits. The
// header's last field names the writer's symbol for name-based hooks.
package main

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"sync/atomic"
	"syscall"
)

var ceValue int32 = 1234567
var cePointer = &ceValue
var spinning atomic.Bool

//go:noinline
func ce_writer() int32 {
	ceValue = ceValue + 1
	return ceValue
}

func main() {
	// PR_SET_PTRACER_ANY: let a separately started tool attach under Yama
	// ptrace_scope=1, as with the C fixture.
	syscall.RawSyscall(syscall.SYS_PRCTL, 0x59616d61, ^uintptr(0), 0)
	writer := reflect.ValueOf(ce_writer).Pointer()
	fmt.Printf("CE_STATIC %d %p %p %#x %s\n", os.Getpid(), &ceValue, &cePointer, writer, runtime.FuncForPC(writer).Name())
	input := bufio.NewReader(os.Stdin)
	for {
		command, err := input.ReadByte()
		if err != nil || command == 'q' {
			return
		}
		switch command {
		case 'b':
			fmt.Println(ce_writer())
		case 'r':
			fmt.Println(ceValue)
		case 's':
			if spinning.CompareAndSwap(false, true) {
				go func() {
					for spinning.Load() {
					}
				}()
			}
			fmt.Println(1)
		case 'x':
			spinning.Store(false)
			fmt.Println(0)
		}
	}
}
