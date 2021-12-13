//go:build linux
// +build linux

package main

import (
	"encoding/binary"
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

// The base of this is artisanal copy pasta from https://github.com/cilium/ebpf/blob/master/examples/tracepoint_in_go/main.go
// Basically, we look to detect the arguments and 'objectClass=*' filter that c_getAttributes sends to the LDAP server
// https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/java.naming/share/classes/com/sun/jndi/ldap/LdapCtx.java#L1354

var progSpec = &ebpf.ProgramSpec{
	Name:    "log4shell_detector",
	Type:    ebpf.TracePoint,
	License: "GPL",
}

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

	// rewrites to make things slightly easier to read
	const (
		GLOBAL_CTX = asm.R9
		GLOBAL_BUF = asm.R8
	)

	progSpec.Instructions = asm.Instructions{
		asm.Mov.Reg(GLOBAL_CTX, asm.R1),

		/*
			Stack:
			-16 - -11: 4 bytes of comm + NULL
			-11 - -4: 7 bytes of sent buf
			-4 - 0: BER read temp (and pid at the end)
		*/

		// zero out stack
		asm.Mov.Imm(asm.R0, 0),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),

		// store 5 (4 + NULL) bytes of comm at FP-16
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Mov.Imm(asm.R2, 5),
		asm.FnGetCurrentComm.Call(),
		// check return?

		// r0 = *(uint32_t *)(FP-16)
		asm.LoadMem(asm.R0, asm.RFP, -16, asm.Word),
		// if r0 == 'java' goto is_java else return 0;
		asm.JEq.Imm(asm.R0, 0x6176616a, "is_java"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		/*
			name: sys_enter_sendto
			format:
				...
				field:void * buff;	offset:24;	size:8;	signed:0;
				field:size_t len;	offset:32;	size:8;	signed:0;
		*/

		// if ctx->len >= 0x44 goto size_ok else return 0;
		asm.LoadMem(asm.R0, GLOBAL_CTX, 32, asm.DWord).Sym("is_java"),
		asm.JGE.Imm(asm.R0, 0x44, "size_ok"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.LoadMem(GLOBAL_BUF, GLOBAL_CTX, 24, asm.DWord).Sym("size_ok"),

		// read 6 bytes of buf
		// FP-11: 0x30 (sequence)
		// FP-10: size
		// FP-9: message id
		// FP-6: 0x63 (searchRequest)

		// bpf_probe_read
		// dst
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -11),
		// size
		asm.Mov.Imm(asm.R2, 6),
		// src
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),

		// if *(char *)(FP-11) == 0x30 goto check2 else return 0;
		asm.LoadMem(asm.R0, asm.RFP, -11, asm.Byte),
		asm.JEq.Imm(asm.R0, 0x30, "check2"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// read the expected searchRequest (0x63) type byte
		// if *(char *)(FP-6) == 0x63 goto is_ldap else return 0;
		asm.LoadMem(asm.R0, asm.RFP, -6, asm.Byte).Sym("check2"),
		asm.JEq.Imm(asm.R0, 0x63, "is_ldap"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// r8 += 7 (to get to the encoding of the baseObject)
		asm.Add.Imm(GLOBAL_BUF, 7).Sym("is_ldap"),

		// read baseObject BER
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),

		// r0 = baseObject length
		asm.LoadMem(asm.R0, asm.RFP, -3, asm.Byte),
		// r8 += type byte, length byte and actual length
		asm.Add.Imm(GLOBAL_BUF, 2),
		asm.Add.Reg(GLOBAL_BUF, asm.R0),

		// start reading the remainder BERs
		// this is basically an unrolled loop checking scope, derefAliases, sizeLimit, timeLimit and typesOnly
		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber1"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x0a00010a, "ber2"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber2"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(GLOBAL_BUF, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x01020301, "ber3"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber3"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(GLOBAL_BUF, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x00010200, "ber4"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber4"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(GLOBAL_BUF, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		// debug leftovers
		// asm.StoreImm(asm.RFP, -4, 0x00006425, asm.Word),
		// asm.Mov.Reg(asm.R1, asm.RFP),
		// asm.Add.Imm(asm.R1, -4),
		// asm.Mov.Imm(asm.R2, 3),
		// asm.Mov.Reg(asm.R3, asm.R0),
		// asm.FnTracePrintk.Call(),

		// -0x78fffeff = struct.unpack('<i', bytes([1, 1, 0, 0x87]))
		// JEq.Imm(asm.R0, -0x78fffeff, "ber5") doesn't work here for some reason...
		asm.Mov.Imm32(asm.R1, -0x78fffeff),
		asm.JEq.Reg(asm.R0, asm.R1, "ber5"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber5"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(GLOBAL_BUF, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		// \x0bobj
		asm.JEq.Imm(asm.R0, 0x6a626f0b, "ber6"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber6"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(GLOBAL_BUF, 4),
		asm.Mov.Reg(asm.R3, GLOBAL_BUF),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		// ectC
		asm.JEq.Imm(asm.R0, 0x43746365, "alert"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// could go further, but matching everything so far should be good enough TM

		asm.FnGetCurrentPidTgid.Call().Sym("alert"),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),

		// perf_event_output
		// ctx
		asm.Mov.Reg(asm.R1, GLOBAL_CTX),
		// map
		asm.LoadMapPtr(asm.R2, events.FD()), // file descriptor of the perf event array
		// flags
		asm.LoadImm(asm.R3, 0xffffffff, asm.DWord),
		// data
		asm.Mov.Reg(asm.R4, asm.RFP),
		asm.Add.Imm(asm.R4, -20),
		// size
		asm.Mov.Imm(asm.R5, 20),
		asm.FnPerfEventOutput.Call(),

		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// buf := bytes.NewBuffer(make([]byte, 0, len(progSpec.Instructions)))
	// _ = progSpec.Instructions.Marshal(buf, binary.LittleEndian)
	// log.Println(buf.Bytes())

	// Instantiate and insert the program into the kernel.
	prog, err := ebpf.NewProgram(progSpec)
	if err != nil {
		log.Fatalf("creating ebpf program: %s", err)
	}
	defer prog.Close()

	// java uses sendto on my machine, but the ctx offsets in the instructions will work for sys_enter_write just as well
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

		pid := binary.LittleEndian.Uint32(record.RawSample[:4])
		log.Println("PID", pid)
	}
}
