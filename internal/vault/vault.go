// Package vault stores named secrets in an age (scrypt) encrypted file and
// keeps decrypted values in locked memory only.
package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"unsafe"

	"filippo.io/age"

	"github.com/toppk/sitescope/internal/secmem"
)

const (
	MaxSize = 64 * 1024
	// 2^15 scrypt needs 32 MiB transiently; the default 2^18 (256 MiB) would blow MemoryMax.
	WorkFactor    = 15
	MaxWorkFactor = 16
	magic         = "SSV1"
)

var (
	ErrWrongPassphrase = errors.New("vault: wrong passphrase")
	ErrNotFound        = errors.New("vault: no such secret")
	validName          = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
)

func ValidName(n string) bool { return validName.MatchString(n) }

// Secrets is a decrypted vault held in one locked buffer.
type Secrets struct {
	buf   *secmem.Buf
	index map[string][2]int
}

func (s *Secrets) Names() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.index))
	for n := range s.index {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// Get returns a heap copy; callers needing the value in a request header can't avoid that.
func (s *Secrets) Get(name string) (string, bool) {
	if s == nil {
		return "", false
	}
	r, ok := s.index[name]
	if !ok {
		return "", false
	}
	return string(s.buf.Bytes()[r[0]:r[1]]), true
}

// With lends the value without copying; fn must not retain it.
func (s *Secrets) With(name string, fn func([]byte)) bool {
	if s == nil {
		return false
	}
	r, ok := s.index[name]
	if ok {
		fn(s.buf.Bytes()[r[0]:r[1]])
	}
	return ok
}

func (s *Secrets) Destroy() {
	if s == nil {
		return
	}
	s.buf.Destroy()
	s.index = nil
}

// parse indexes an encoded vault in place: magic, then [u16 name len][name][u32 value len][value]...
func parse(buf *secmem.Buf, n int) (*Secrets, error) {
	b := buf.Bytes()[:n]
	if n < len(magic) || string(b[:len(magic)]) != magic {
		return nil, errors.New("vault: bad format")
	}
	s := &Secrets{buf: buf, index: map[string][2]int{}}
	off := len(magic)
	for off < n {
		if off+2 > n {
			return nil, errors.New("vault: truncated")
		}
		nl := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if off+nl+4 > n {
			return nil, errors.New("vault: truncated")
		}
		name := string(b[off : off+nl])
		off += nl
		vl := int(binary.BigEndian.Uint32(b[off:]))
		off += 4
		if off+vl > n {
			return nil, errors.New("vault: truncated")
		}
		s.index[name] = [2]int{off, off + vl}
		off += vl
	}
	return s, nil
}

func passString(pass []byte) string { return unsafe.String(unsafe.SliceData(pass), len(pass)) }

// Decrypt reads an encrypted vault straight into locked memory.
func Decrypt(r io.Reader, pass []byte) (*Secrets, error) {
	if len(pass) == 0 {
		return nil, ErrWrongPassphrase
	}
	id, err := age.NewScryptIdentity(passString(pass))
	if err != nil {
		return nil, err
	}
	id.SetMaxWorkFactor(MaxWorkFactor)
	dr, err := age.Decrypt(r, id)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrWrongPassphrase
		}
		return nil, fmt.Errorf("vault: %w", err)
	}
	buf, err := secmem.New(MaxSize + 1)
	if err != nil {
		return nil, err
	}
	n, err := io.ReadFull(dr, buf.Bytes())
	if err == nil {
		buf.Destroy()
		return nil, errors.New("vault: larger than 64 KiB")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		buf.Destroy()
		return nil, fmt.Errorf("vault: %w", err)
	}
	s, err := parse(buf, n)
	if err != nil {
		buf.Destroy()
		return nil, err
	}
	return s, nil
}

func Load(path string, pass []byte) (*Secrets, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Decrypt(f, pass)
}

// Edit is a pending change set for Save; values are copied into locked memory.
type Edit struct {
	set map[string]*secmem.Buf
	n   map[string]int
	rm  map[string]bool
}

func NewEdit() *Edit {
	return &Edit{set: map[string]*secmem.Buf{}, n: map[string]int{}, rm: map[string]bool{}}
}

func (e *Edit) Set(name string, value []byte) error {
	if !ValidName(name) {
		return fmt.Errorf("vault: invalid name %q", name)
	}
	b, err := secmem.New(len(value))
	if err != nil {
		return err
	}
	copy(b.Bytes(), value)
	e.set[name].Destroy()
	e.set[name], e.n[name] = b, len(value)
	delete(e.rm, name)
	return nil
}

func (e *Edit) Remove(name string) {
	e.set[name].Destroy()
	delete(e.set, name)
	e.rm[name] = true
}

func (e *Edit) Destroy() {
	for _, b := range e.set {
		b.Destroy()
	}
}

// Encrypt writes base with edit applied as an age file to w.
func Encrypt(w io.Writer, pass []byte, base *Secrets, edit *Edit) error {
	if len(pass) == 0 {
		return errors.New("vault: empty passphrase")
	}
	type entry struct {
		name  string
		value []byte
	}
	var entries []entry
	for _, n := range base.Names() {
		if edit != nil && (edit.rm[n] || edit.set[n] != nil) {
			continue
		}
		r := base.index[n]
		entries = append(entries, entry{n, base.buf.Bytes()[r[0]:r[1]]})
	}
	if edit != nil {
		for n, b := range edit.set {
			entries = append(entries, entry{n, b.Bytes()[:edit.n[n]]})
		}
	}
	size := len(magic)
	for _, e := range entries {
		size += 2 + len(e.name) + 4 + len(e.value)
	}
	if size > MaxSize {
		return errors.New("vault: larger than 64 KiB")
	}
	buf, err := secmem.New(size)
	if err != nil {
		return err
	}
	defer buf.Destroy()
	b := buf.Bytes()
	off := copy(b, magic)
	for _, e := range entries {
		binary.BigEndian.PutUint16(b[off:], uint16(len(e.name)))
		off += 2
		off += copy(b[off:], e.name)
		binary.BigEndian.PutUint32(b[off:], uint32(len(e.value)))
		off += 4
		off += copy(b[off:], e.value)
	}
	rcpt, err := age.NewScryptRecipient(passString(pass))
	if err != nil {
		return err
	}
	rcpt.SetWorkFactor(WorkFactor)
	aw, err := age.Encrypt(w, rcpt)
	if err != nil {
		return err
	}
	if _, err := aw.Write(b[:off]); err != nil {
		return err
	}
	return aw.Close()
}

// Save atomically replaces path; plaintext only ever exists in memory.
func Save(path string, pass []byte, base *Secrets, edit *Edit) error {
	var out bytes.Buffer
	if err := Encrypt(&out, pass, base, edit); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".vault-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(out.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}
