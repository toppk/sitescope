package agent

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/toppk/sitescope/internal/report"
)

const cacheFor = 10 * time.Second

type Server struct {
	Collector *Collector
	Token     string
	Version   string
	Peers     map[string]string // WireGuard public key -> host name, for metric labels

	mu     sync.Mutex
	cached *report.Report
	at     time.Time
	errs   map[string]uint64
}

func (s *Server) report(ctx context.Context) *report.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil || time.Since(s.at) > cacheFor {
		s.cached, s.at = s.Collector.Collect(ctx), time.Now()
		if s.errs == nil {
			s.errs = map[string]uint64{}
		}
		for section := range s.cached.Errors {
			s.errs[section]++
		}
	}
	return s.cached
}

func (s *Server) errCounts() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.errs))
	for k, v := range s.errs {
		out[k] = v
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok\n"))
		return
	}
	if (r.URL.Path != "/v1/report" && r.URL.Path != "/metrics") || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	got := r.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+s.Token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	rep := s.report(r.Context())
	if r.URL.Path == "/metrics" {
		var b bytes.Buffer
		WriteMetrics(&b, rep, s.Peers, s.errCounts(), s.Version, time.Now())
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Write(b.Bytes())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rep)
}

// Listen binds with IP_FREEBIND so the agent can start before wg0 has its address.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			serr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_FREEBIND, 1)
		})
		return errors.Join(err, serr)
	}}
	return lc.Listen(ctx, "tcp", addr)
}

// certFile serves a key pair from disk, reloading it when the cert's mtime changes.
type certFile struct {
	cert, key string
	mu        sync.Mutex
	mtime     time.Time
	pair      *tls.Certificate
}

func (c *certFile) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := os.Stat(c.cert)
	if err != nil {
		return nil, err
	}
	if c.pair == nil || !st.ModTime().Equal(c.mtime) {
		pair, err := tls.LoadX509KeyPair(c.cert, c.key)
		if err != nil {
			return nil, err
		}
		c.pair, c.mtime = &pair, st.ModTime()
	}
	return c.pair, nil
}

// TLSConfig is nil when the agent serves plain HTTP.
func TLSConfig(cert, key string) (*tls.Config, error) {
	if cert == "" && key == "" {
		return nil, nil
	}
	if cert == "" || key == "" {
		return nil, errors.New("agent.tlsCert and agent.tlsKey go together")
	}
	cf := &certFile{cert: cert, key: key}
	if _, err := cf.get(nil); err != nil {
		return nil, err
	}
	return &tls.Config{GetCertificate: cf.get, MinVersion: tls.VersionTLS12}, nil
}

func Run(ctx context.Context, addr string, s *Server, tc *tls.Config) error {
	if s.Token == "" {
		return errors.New("SITESCOPE_AGENT_TOKEN is not set")
	}
	if addr == "" {
		return errors.New("agent.listen is not set")
	}
	ln, err := Listen(ctx, addr)
	if err != nil {
		return err
	}
	if tc != nil {
		ln = tls.NewListener(ln, tc)
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	slog.Info("agent listening", "addr", addr, "tls", tc != nil)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
