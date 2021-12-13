//go:build linux
// +build linux

package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

// Artisanal copy pasta from https://github.com/cilium/ebpf/blob/master/examples/tracepoint_in_go/main.go

var progSpec = &ebpf.ProgramSpec{
	Name:    "log4shell_detector",
	Type:    ebpf.TracePoint,
	License: "GPL",
}

/*
name: sys_enter_sendto
format:
	field:unsigned short common_type;	offset:0;	size:2;	signed:0;
	field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
	field:unsigned char common_preempt_count;	offset:3;	size:1;signed:0;
	field:int common_pid;	offset:4;	size:4;	signed:1;

	field:int __syscall_nr;	offset:8;	size:4;	signed:1;
	field:int fd;	offset:16;	size:8;	signed:0;
	field:void * buff;	offset:24;	size:8;	signed:0;
	field:size_t len;	offset:32;	size:8;	signed:0;
	field:unsigned int flags;	offset:40;	size:8;	signed:0;
	field:struct sockaddr * addr;	offset:48;	size:8;	signed:0;
	field:int addr_len;	offset:56;	size:8;	signed:0;
*/

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Create a perf event array for the kernel to write perf records to.
	// These records will be read by userspace below.
	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.PerfEventArray,
		Name: "log4shell_detect_pids",
	})
	if err != nil {
		log.Fatalf("creating perf event array: %s", err)
	}
	defer events.Close()

	// Open a perf reader from userspace into the perf event array
	// created earlier.
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()

	// Close the reader when the process receives a signal, which will exit
	// the read loop.
	go func() {
		<-stopper
		rd.Close()
	}()

	progSpec.Instructions = asm.Instructions{
		// r9 = ctx
		asm.Mov.Reg(asm.R9, asm.R1),

		// store 4 bytes of comm at FP-8
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 4),
		asm.FnGetCurrentComm.Call(),
		// check return?

		// r0 = *(uint32_t *)(FP-8)
		asm.LoadMem(asm.R0, asm.RFP, -8, asm.Word),
		// if r0 == 'java' goto is_java else return 0;
		asm.JEq.Imm(asm.R0, 0x6176616a, "is_java"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// r0 = ctx->len
		asm.LoadMem(asm.R0, asm.R9, 32, asm.DWord).Sym("is_java"),
		// if r0 >= 0x44 goto size_ok else return 0;
		asm.JGE.Imm(asm.R0, 0x44, "size_ok"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// r8 = ctx->buf
		asm.LoadMem(asm.R8, asm.R9, 24, asm.DWord).Sym("size_ok"),
		// bpf_probe_read
		// dst
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -8),
		// size
		asm.Mov.Imm(asm.R2, 2),
		// src
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		// TODO: check return

		// r0 = *(uint16_t *)(FP-8)
		asm.LoadMem(asm.R0, asm.RFP, -8, asm.Half),
		// if r0 == 0x4330 goto is_ldap else return 0;
		asm.JEq.Imm(asm.R0, 0x4330, "is_ldap"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// perf_event_output
		// ctx
		asm.Mov.Reg(asm.R1, asm.R9).Sym("is_ldap"),
		// map
		asm.LoadMapPtr(asm.R2, events.FD()), // file descriptor of the perf event array
		// flags
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		// data
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -8),
		// size
		asm.Mov.Imm(asm.R5, 4),
		asm.FnPerfEventOutput.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Instantiate and insert the program into the kernel.
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}
	defer prog.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_sendto", prog)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()

	log.Println("Waiting for events..")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		log.Println("Record:", record)
	}
}
