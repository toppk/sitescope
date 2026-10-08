package hub

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/toppk/sitescope/internal/config"
)

type Mailer struct {
	cfg  config.Alerts
	host string
	url  string
}

func (m *Mailer) Name() string { return "email" }

func (m *Mailer) Enabled() bool { return m.cfg.Enabled && len(m.cfg.To) > 0 }

// Send submits to the local MTA without TLS or auth: it is loopback and postfix signs with DKIM.
func (m *Mailer) Send(msg Message) error { return m.send(msg.Subject, msg.Body) }

func (m *Mailer) send(subject, body string) error {
	conn, err := net.DialTimeout("tcp", m.cfg.SMTP, 10*time.Second)
	if err != nil {
		return err
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	host, _, _ := net.SplitHostPort(m.cfg.SMTP)
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if err := c.Hello(m.host); err != nil {
		return err
	}
	if err := c.Mail(m.cfg.From); err != nil {
		return err
	}
	for _, to := range m.cfg.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(m.message(subject, body, time.Now())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (m *Mailer) message(subject, body string, now time.Time) []byte {
	id := make([]byte, 12)
	rand.Read(id)
	domain := m.cfg.From[strings.LastIndex(m.cfg.From, "@")+1:]
	var b strings.Builder
	hdr := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }
	hdr("From", "sitescope <"+m.cfg.From+">")
	hdr("To", strings.Join(m.cfg.To, ", "))
	hdr("Subject", strings.TrimSpace(m.cfg.SubjectPrefix+" "+subject))
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	hdr("Auto-Submitted", "auto-generated")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	if m.url != "" {
		b.WriteString("\r\n-- \r\n" + strings.TrimSuffix(m.url, "/") + "/detail\r\n")
	}
	return []byte(b.String())
}
