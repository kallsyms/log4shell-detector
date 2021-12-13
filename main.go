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

// Framework is artisanal copy pasta from https://github.com/cilium/ebpf/blob/master/examples/tracepoint_in_go/main.go
// Basically, we look to detect the arguments and 'objectClass=*' filter that c_getAttributes sends to the LDAP server
// https://github.com/AdoptOpenJDK/openjdk-jdk11u/blob/fa3ecefdd6eb14a910ae75b7c0aefb1cf8eedcce/src/java.naming/share/classes/com/sun/jndi/ldap/LdapCtx.java#L1354

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
		/*
			Globals:
			r9 = ctx
			r8 = buf

			Stack:
			-16 - -11: 4 bytes of comm + NULL
			-11 - -4: 7 bytes of sent buf
			-4 - 0: BER read temp (and pid at the end)
		*/

		// r9 = ctx
		asm.Mov.Reg(asm.R9, asm.R1),

		// zero out stack
		asm.Mov.Imm(asm.R0, 0),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),

		// store 4+1 (NULL) bytes of comm at FP-16
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

		// if ctx->len >= 0x44 goto size_ok else return 0;
		asm.LoadMem(asm.R0, asm.R9, 32, asm.DWord).Sym("is_java"),
		asm.JGE.Imm(asm.R0, 0x44, "size_ok"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// r8 = ctx->buf
		asm.LoadMem(asm.R8, asm.R9, 24, asm.DWord).Sym("size_ok"),
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
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		// TODO: check return

		// if (*char*)(FP-11) == 0x30 goto check2 else return 0;
		asm.LoadMem(asm.R0, asm.RFP, -11, asm.Byte),
		asm.JEq.Imm(asm.R0, 0x30, "check2"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// read both the expected searchRequest (0x63) and the length
		// if *(char *)(FP-6) == 0x63 goto is_ldap else return 0;
		asm.LoadMem(asm.R0, asm.RFP, -6, asm.Byte).Sym("check2"),
		asm.JEq.Imm(asm.R0, 0x63, "is_ldap"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		// r6 += 7 (to get to the encoding of the baseObject)
		asm.Add.Imm(asm.R8, 7).Sym("is_ldap"),

		// read baseObject BER
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),

		// r0 = baseObject length
		asm.LoadMem(asm.R0, asm.RFP, -3, asm.Byte),
		// r8 += type byte, length byte and actual length
		asm.Add.Imm(asm.R8, 2),
		asm.Add.Reg(asm.R8, asm.R0),

		// start reading the remainder BERs
		// this is basically an unrolled loop checking scope, derefAliases, sizeLimit, timeLimit and typesOnly
		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber1"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x0a00010a, "ber2"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber2"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(asm.R8, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x01020301, "ber3"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber3"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(asm.R8, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x00010200, "ber4"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber4"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(asm.R8, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		// -0x78fffeff = struct.unpack('<i', bytes([1, 1, 0, 0x87]))
		// asm.JEq.Imm(asm.R0, -0x78fffeff, "ber5"),
		// asm.Mov.Imm(asm.R0, 0),
		// asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber5"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(asm.R8, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x6a626f0b, "ber6"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		asm.Mov.Reg(asm.R1, asm.RFP).Sym("ber6"),
		asm.Add.Imm(asm.R1, -4),
		asm.Mov.Imm(asm.R2, 4),
		asm.Add.Imm(asm.R8, 4),
		asm.Mov.Reg(asm.R3, asm.R8),
		asm.FnProbeRead.Call(),
		asm.LoadMem(asm.R0, asm.RFP, -4, asm.Word),

		asm.JEq.Imm(asm.R0, 0x43746365, "alert"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),

		//asm.LoadMem(asm.R0, asm.R9, 4, asm.Word).Sym("alert"),
		asm.FnGetCurrentPidTgid.Call().Sym("alert"),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),

		// perf_event_output
		// ctx
		asm.Mov.Reg(asm.R1, asm.R9),
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

		pid := binary.LittleEndian.Uint32(record.RawSample[:4])
		log.Println("PID", pid)
	}
}
