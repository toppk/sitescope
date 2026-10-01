package hub

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/secmem"
)

// ReadSecret prompts on the controlling terminal with echo off and reads one
// line into locked memory.
func ReadSecret(prompt string) (*secmem.Buf, int, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("no terminal for the passphrase prompt: %w", err)
	}
	defer tty.Close()
	return readLine(tty, prompt, true)
}

// ReadStdinSecret reads a value from stdin: prompted with echo off on a
// terminal, otherwise everything up to EOF minus one trailing newline.
func ReadStdinSecret(prompt string, max int) (*secmem.Buf, int, error) {
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS); err == nil {
		return readLine(os.Stdin, prompt, false)
	}
	buf, err := secmem.New(max + 1)
	if err != nil {
		return nil, 0, err
	}
	n := 0
	for n < len(buf.Bytes()) {
		m, err := os.Stdin.Read(buf.Bytes()[n:])
		n += m
		if err != nil {
			break
		}
	}
	if n > max {
		buf.Destroy()
		return nil, 0, errors.New("value too large")
	}
	if n > 0 && buf.Bytes()[n-1] == '\n' {
		n--
	}
	return buf, n, nil
}

func readLine(f *os.File, prompt string, promptToFile bool) (*secmem.Buf, int, error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, 0, err
	}
	noecho := *old
	noecho.Lflag &^= unix.ECHO
	noecho.Lflag |= unix.ICANON | unix.ECHONL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &noecho); err != nil {
		return nil, 0, err
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, old)
	if promptToFile {
		fmt.Fprint(f, prompt)
	} else {
		fmt.Fprint(os.Stderr, prompt)
	}
	buf, err := secmem.New(4096)
	if err != nil {
		return nil, 0, err
	}
	n := 0
	for n < len(buf.Bytes()) {
		m, err := f.Read(buf.Bytes()[n:])
		n += m
		if n > 0 && buf.Bytes()[n-1] == '\n' {
			return buf, n - 1, nil
		}
		if err != nil || m == 0 {
			break
		}
	}
	buf.Destroy()
	return nil, 0, errors.New("no input")
}
