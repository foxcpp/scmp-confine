package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/go-yaml/yaml"
	seccomp "github.com/seccomp/libseccomp-golang"
)

type Cfg struct {
	PermitEscalation bool `yaml:"permit_escalation"`

	KillCalls  StringList `yaml:"kill_calls"`
	TrapCalls  StringList `yaml:"trap_calls"`
	ErrnoCalls StringList `yaml:"errno_calls"`
	AllowCalls StringList `yaml:"allow_calls"`
	LogCalls   StringList `yaml:"log_calls"`

	DefaultAct Action `yaml:"default_action"`
	Errno      Errno  `yaml:"errno"`
}

func (cfg *Cfg) Set(s string) error {
	f, err := os.Open(s)
	if err != nil {
		return err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.SetStrict(true)
	return d.Decode(cfg)
}

func (cfg *Cfg) String() string {
	return ""
}

// Generated using a small Vim macro from 'errno --list' output.

var errnoMap = map[string]int16{
	"ESUCCESS":        0,
	"EPERM":           1,
	"ENOENT":          2,
	"ESRCH":           3,
	"EINTR":           4,
	"EIO":             5,
	"ENXIO":           6,
	"E2BIG":           7,
	"ENOEXEC":         8,
	"EBADF":           9,
	"ECHILD":          10,
	"EAGAIN":          11,
	"ENOMEM":          12,
	"EACCES":          13,
	"EFAULT":          14,
	"ENOTBLK":         15,
	"EBUSY":           16,
	"EEXIST":          17,
	"EXDEV":           18,
	"ENODEV":          19,
	"ENOTDIR":         20,
	"EISDIR":          21,
	"EINVAL":          22,
	"ENFILE":          23,
	"EMFILE":          24,
	"ENOTTY":          25,
	"ETXTBSY":         26,
	"EFBIG":           27,
	"ENOSPC":          28,
	"ESPIPE":          29,
	"EROFS":           30,
	"EMLINK":          31,
	"EPIPE":           32,
	"EDOM":            33,
	"ERANGE":          34,
	"EDEADLK":         35,
	"ENAMETOOLONG":    36,
	"ENOLCK":          37,
	"ENOSYS":          38,
	"ENOTEMPTY":       39,
	"ELOOP":           40,
	"EWOULDBLOCK":     11,
	"ENOMSG":          42,
	"EIDRM":           43,
	"ECHRNG":          44,
	"EL2NSYNC":        45,
	"EL3HLT":          46,
	"EL3RST":          47,
	"ELNRNG":          48,
	"EUNATCH":         49,
	"ENOCSI":          50,
	"EL2HLT":          51,
	"EBADE":           52,
	"EBADR":           53,
	"EXFULL":          54,
	"ENOANO":          55,
	"EBADRQC":         56,
	"EBADSLT":         57,
	"EDEADLOCK":       35,
	"EBFONT":          59,
	"ENOSTR":          60,
	"ENODATA":         61,
	"ETIME":           62,
	"ENOSR":           63,
	"ENONET":          64,
	"ENOPKG":          65,
	"EREMOTE":         66,
	"ENOLINK":         67,
	"EADV":            68,
	"ESRMNT":          69,
	"ECOMM":           70,
	"EPROTO":          71,
	"EMULTIHOP":       72,
	"EDOTDOT":         73,
	"EBADMSG":         74,
	"EOVERFLOW":       75,
	"ENOTUNIQ":        76,
	"EBADFD":          77,
	"EREMCHG":         78,
	"ELIBACC":         79,
	"ELIBBAD":         80,
	"ELIBSCN":         81,
	"ELIBMAX":         82,
	"ELIBEXEC":        83,
	"EILSEQ":          84,
	"ERESTART":        85,
	"ESTRPIPE":        86,
	"EUSERS":          87,
	"ENOTSOCK":        88,
	"EDESTADDRREQ":    89,
	"EMSGSIZE":        90,
	"EPROTOTYPE":      91,
	"ENOPROTOOPT":     92,
	"EPROTONOSUPPORT": 93,
	"ESOCKTNOSUPPORT": 94,
	"EOPNOTSUPP":      95,
	"EPFNOSUPPORT":    96,
	"EAFNOSUPPORT":    97,
	"EADDRINUSE":      98,
	"EADDRNOTAVAIL":   99,
	"ENETDOWN":        100,
	"ENETUNREACH":     101,
	"ENETRESET":       102,
	"ECONNABORTED":    103,
	"ECONNRESET":      104,
	"ENOBUFS":         105,
	"EISCONN":         106,
	"ENOTCONN":        107,
	"ESHUTDOWN":       108,
	"ETOOMANYREFS":    109,
	"ETIMEDOUT":       110,
	"ECONNREFUSED":    111,
	"EHOSTDOWN":       112,
	"EHOSTUNREACH":    113,
	"EALREADY":        114,
	"EINPROGRESS":     115,
	"ESTALE":          116,
	"EUCLEAN":         117,
	"ENOTNAM":         118,
	"ENAVAIL":         119,
	"EISNAM":          120,
	"EREMOTEIO":       121,
	"EDQUOT":          122,
	"ENOMEDIUM":       123,
	"EMEDIUMTYPE":     124,
	"ECANCELED":       125,
	"ENOKEY":          126,
	"EKEYEXPIRED":     127,
	"EKEYREVOKED":     128,
	"EKEYREJECTED":    129,
	"EOWNERDEAD":      130,
	"ENOTRECOVERABLE": 131,
	"ERFKILL":         132,
	"EHWPOISON":       133,
	"ENOTSUP":         95,
}

type Errno int16

func NewErrno(s string) (Errno, error) {
	if num, err := strconv.ParseInt(s, 10, 16); err == nil {
		return Errno(num), nil
	}

	s = strings.ToUpper(s)
	if !strings.HasPrefix(s, "E") {
		s = "E" + s
	}

	val, ok := errnoMap[s]
	if !ok {
		return 0, fmt.Errorf("unknown errno value: %s", s)
	}

	return Errno(val), nil
}

func (e *Errno) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	val, err := NewErrno(s)
	if err != nil {
		return err
	}

	*(*int16)(e) = int16(val)
	return nil
}

// Set implements flag.Value
func (e *Errno) Set(s string) error {
	val, err := NewErrno(s)
	if err != nil {
		return err
	}
	*e = val
	return nil
}

func (e *Errno) String() string {
	for k, v := range errnoMap {
		if v == int16(*e) {
			return k
		}
	}
	panic("unknown errno")
}

type Action seccomp.ScmpAction

func NewAction(s string) (Action, error) {
	switch s {
	case "kill":
		return Action(seccomp.ActKill), nil
	case "trap":
		return Action(seccomp.ActTrap), nil
	case "errno":
		return Action(seccomp.ActErrno), nil
	case "allow":
		return Action(seccomp.ActAllow), nil
	case "log":
		return Action(seccomp.ActLog), nil
	default:
		return 0, fmt.Errorf("unknown action: %s", s)
	}
}

func (a *Action) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	val, err := NewAction(s)
	if err != nil {
		return err
	}
	*a = val

	return nil
}

// Set implements flag.Value
func (a *Action) Set(s string) error {
	val, err := NewAction(s)
	if err != nil {
		return err
	}
	*a = val
	return nil
}

func (a *Action) String() string {
	switch seccomp.ScmpAction(*a) {
	case seccomp.ActKill:
		return "kill"
	case seccomp.ActTrap:
		return "trap"
	case seccomp.ActErrno:
		return "errno"
	case seccomp.ActAllow:
		return "allow"
	case seccomp.ActLog:
		return "log"
	}
	return "???"
}

type StringList []string

// Set implements flag.Value
func (l *StringList) Set(s string) error {
	*(*[]string)(l) = append([]string(*l), strings.Split(s, ",")...)
	return nil
}

func (l *StringList) String() string {
	return strings.Join([]string(*l), ",")
}

func (l *StringList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s []string
	if err := unmarshal(&s); err != nil {
		return err
	}

	*(*[]string)(l) = append([]string(*l), s...)

	return nil
}
