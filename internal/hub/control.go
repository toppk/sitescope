package hub

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/secmem"
	"github.com/toppk/sitescope/internal/vault"
)

const maxPassphrase = 1024

// serveControl accepts operator commands on a unix socket: status, lock, unlock.
func (h *Hub) serveControl(ctx context.Context) error {
	path := h.cfg.Hub.ControlSocket
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	go func() { <-ctx.Done(); ln.Close() }()
	if err := os.Chmod(path, 0o660); err != nil {
		return err
	}
	if g := h.cfg.Hub.ControlGroup; g != "" {
		grp, err := user.LookupGroup(g)
		if err != nil {
			return fmt.Errorf("control group: %w", err)
		}
		gid, _ := strconv.Atoi(grp.Gid)
		if err := os.Chown(path, -1, gid); err != nil {
			return fmt.Errorf("control socket chown to %s: %w", g, err)
		}
	}
	slog.Info("control socket ready", "path", path)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go h.control(conn.(*net.UnixConn))
	}
}

func peerUID(c *net.UnixConn) string {
	raw, err := c.SyscallConn()
	if err != nil {
		return "?"
	}
	uid := "?"
	raw.Control(func(fd uintptr) {
		if cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED); err == nil {
			uid = strconv.Itoa(int(cred.Uid))
		}
	})
	return uid
}

func (h *Hub) control(c *net.UnixConn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Minute))
	uid := peerUID(c)
	r := bufio.NewReaderSize(c, 64)
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	reply := func(f string, a ...any) { fmt.Fprintf(c, f+"\n", a...) }
	switch strings.TrimSpace(line) {
	case "status":
		state := "locked"
		if h.vault.Unlocked() {
			state = "unlocked (" + strings.Join(h.vault.Names(), ", ") + ")"
		}
		reply("ok vault %s, %d checks", state, len(h.checks))
	case "lock":
		h.vault.Lock()
		slog.Info("vault locked", "uid", uid)
		reply("ok locked")
	case "unlock":
		buf, err := secmem.New(maxPassphrase)
		if err != nil {
			reply("err %v", err)
			return
		}
		defer buf.Destroy()
		n, err := io.ReadFull(r, buf.Bytes())
		if err == nil {
			reply("err passphrase too long")
			return
		}
		if !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			reply("err %v", err)
			return
		}
		switch err := h.vault.Unlock(buf.Bytes()[:n]); {
		case errors.Is(err, vault.ErrWrongPassphrase):
			slog.Warn("unlock failed: wrong passphrase", "uid", uid)
			time.Sleep(2 * time.Second)
			reply("err wrong passphrase")
		case errors.Is(err, os.ErrNotExist):
			reply("err no vault at %s; create it with: sitescope vault set NAME", h.cfg.Hub.Vault)
		case err != nil:
			slog.Error("unlock failed", "uid", uid, "err", err)
			reply("err unlock failed")
		default:
			slog.Info("vault unlocked", "uid", uid, "secrets", len(h.vault.Names()))
			reply("ok unlocked, %d secrets", len(h.vault.Names()))
		}
	default:
		reply("err unknown command")
	}
}
