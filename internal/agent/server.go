package agent

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
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

	mu     sync.Mutex
	cached *report.Report
	at     time.Time
}

func (s *Server) report(ctx context.Context) *report.Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached == nil || time.Since(s.at) > cacheFor {
		s.cached, s.at = s.Collector.Collect(ctx), time.Now()
	}
	return s.cached
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Write([]byte("ok\n"))
		return
	}
	if r.URL.Path != "/v1/report" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	got := r.Header.Get("Authorization")
	if subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+s.Token)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.report(r.Context()))
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

func Run(ctx context.Context, addr string, s *Server) error {
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
	srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 30 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	slog.Info("agent listening", "addr", addr)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
