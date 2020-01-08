package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/seccomp/libseccomp-golang"
)

func buildFilter(cfg Cfg, binaryPath string) (*seccomp.ScmpFilter, error) {
	filter, err := seccomp.NewFilter(seccomp.ScmpAction(cfg.DefaultAct))
	if err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}

	seenCalls := make(map[string]struct{})

	if err := filter.SetNoNewPrivsBit(!cfg.PermitEscalation); err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}

	addRules := func(act seccomp.ScmpAction, list []string) error {
		for _, call := range list {
			call = strings.ToLower(call)

			if _, ok := seenCalls[call]; ok {
				return fmt.Errorf("multiple rules for %s", call)
			}

			callId, err := seccomp.GetSyscallFromName(call)
			if err != nil {
				return fmt.Errorf("add rule for %s: %w", call, err)
			}
			if err := filter.AddRule(callId, act); err != nil {
				return fmt.Errorf("add rule for %s: %w", call, err)
			}

			seenCalls[call] = struct{}{}
		}
		return nil
	}

	if err := addRules(seccomp.ActKill, cfg.KillCalls); err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}
	if err := addRules(seccomp.ActTrap, cfg.TrapCalls); err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}
	if err := addRules(seccomp.ActErrno.SetReturnCode(int16(cfg.Errno)), cfg.ErrnoCalls); err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}
	if err := addRules(seccomp.ActAllow, cfg.AllowCalls); err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}
	if err := addRules(seccomp.ActLog, cfg.LogCalls); err != nil {
		return nil, fmt.Errorf("filter generation failed: %w", err)
	}

	for _, call := range runtimeSyscalls {
		if _, ok := seenCalls[call]; ok {
			continue
		}

		callId, err := seccomp.GetSyscallFromName(call)
		if err != nil {
			return nil, fmt.Errorf("filter generation failed: add rule for %s: %w", call, err)
		}
		if err := filter.AddRule(callId, seccomp.ActAllow); err != nil {
			return nil, fmt.Errorf("filter generation failed: add rule for %s: %w", call, err)
		}
	}

	return filter, nil
}

// System calls that can be used by Go runtime before we run execve().
var runtimeSyscalls = []string{
	"futex",
	"nanosleep",
	"restart_syscall",
	"epoll_wait",
	"epoll_pwait",
	"rt_sigprocmask",
}

func minimizeRuntime() {
	/* Attempt to minimize Go runtime interference after filter.Load */

	debug.FreeOSMemory()
	runtime.GC()
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()
	debug.SetGCPercent(0)
}

func main() {
	minimizeRuntime()

	cfg := Cfg{
		DefaultAct: Action(seccomp.ActErrno),
		Errno:      Errno(1), /* EPERM */
	}
	flag.Var(&cfg, "config", "Load arguments from configuration file")
	flag.BoolVar(&cfg.PermitEscalation, "permit-escalation", false, "Do not set 'no new privileges' bit")
	flag.Var(&cfg.KillCalls, "kill-calls", "Command-separated list of calls to kill process on")
	flag.Var(&cfg.TrapCalls, "trap-calls", "Command-separated list of calls to send SIGSYS on")
	flag.Var(&cfg.ErrnoCalls, "errno-calls", "Command-separated list of calls to return error on")
	flag.Var(&cfg.AllowCalls, "allow-calls", "Command-separated list of system calls to allow without restrictions")
	flag.Var(&cfg.LogCalls, "log-calls", "Command-separated list of system calls to log to audit log")
	flag.Var(&cfg.DefaultAct, "default-act", "Action to apply for all other system calls. Valid values: kill, trap, errno, allow, log")
	flag.Var(&cfg.Errno, "errno", "Error to return when 'errno' action is used")
	dumpPFC := flag.Bool("dump-pfc", false, "Dump generated filter in PFC format to stdout")
	dumpBPF := flag.Bool("dump-bpf", false, "Dump generated filter in BPF format to stdout")
	flag.Parse()
	cmd := flag.Args()
	if len(cmd) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <command> [command args...]", os.Args[0])
		os.Exit(2)
	}

	filter, err := buildFilter(cfg, cmd[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if *dumpPFC {
		if err := filter.ExportPFC(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if *dumpBPF {
		if err := filter.ExportBPF(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	executable, err := exec.LookPath(cmd[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := filter.Load(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	err = syscall.Exec(executable, cmd, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
