# scmp-confine

Simple CLI wrapper for libseccomp library written in Go.

## Installation

- Go 1.11
- C compiler
- libseccomp library and headers

```
go get github.com/foxcpp/scmp-confine
```

## Usage

See `-help` output:
```
Usage of ./scmp-confine:
  -allow-calls value
    	Command-separated list of system calls to allow without restrictions
  -config value
    	Load arguments from configuration file
  -default-act value
    	Action to apply for all other system calls. Valid values: kill, trap, errno, allow, log (default errno)
  -dump-bpf
    	Dump generated filter in BPF format to stdout
  -dump-pfc
    	Dump generated filter in PFC format to stdout
  -errno value
    	Error to return when 'errno' action is used (default EPERM)
  -errno-calls value
    	Command-separated list of calls to return error on
  -kill-calls value
    	Command-separated list of calls to kill process on
  -log-calls value
    	Command-separated list of system calls to log to audit log
  -permit-escalation
    	Do not set 'no new privileges' bit
  -trap-calls value
    	Command-separated list of calls to send SIGSYS on
```

```
$ scmp-confine -config /etc/scmp-confine/usr.bin.telegram-desktop.yml /usr/bin/telegram-desktop
```

## Configuration files

Example of configuration file that can be used with the `-config` argument.

```yaml
default_action: errno
errno: EPERM
permit_escalation: false
allow_calls:
- poll
errno_calls:
- setuid
kill_calls:
- seccomp
log_calls:
- open
```

If `-config` is used with other arguments, command line arguments overrid
configuration values for singular options, lists are concatenated.
