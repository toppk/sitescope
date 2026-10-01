// Package store keeps check history and alert state in a bbolt file.
package store

import (
	"encoding/binary"
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/toppk/sitescope/internal/alert"
	"github.com/toppk/sitescope/internal/status"
)

const maxMessage = 300

var (
	bState = []byte("state")
	bHist  = []byte("history")
	bMeta  = []byte("meta")
)

type Store struct{ db *bolt.DB }

type Entry struct {
	Time    time.Time     `json:"time"`
	Status  status.Status `json:"status"`
	TookMS  uint32        `json:"tookMs"`
	Message string        `json:"message"`
}

func Open(path string) (*Store, error) {
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bState, bHist, bMeta} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func key(t time.Time) []byte {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, uint64(t.UnixNano()))
	return k
}

func encode(e Entry) []byte {
	msg := e.Message
	if len(msg) > maxMessage {
		msg = msg[:maxMessage]
	}
	v := make([]byte, 5+len(msg))
	v[0] = byte(e.Status)
	binary.BigEndian.PutUint32(v[1:], e.TookMS)
	copy(v[5:], msg)
	return v
}

func decode(k, v []byte) Entry {
	e := Entry{Time: time.Unix(0, int64(binary.BigEndian.Uint64(k)))}
	if len(v) >= 5 {
		e.Status = status.Status(v[0])
		e.TookMS = binary.BigEndian.Uint32(v[1:])
		e.Message = string(v[5:])
	}
	return e
}

// Record saves a result and the check's state in one transaction.
func (s *Store) Record(id string, e Entry, st *alert.State) error {
	sv, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bState).Put([]byte(id), sv); err != nil {
			return err
		}
		if e.Time.IsZero() {
			return nil
		}
		h, err := tx.Bucket(bHist).CreateBucketIfNotExists([]byte(id))
		if err != nil {
			return err
		}
		return h.Put(key(e.Time), encode(e))
	})
}

func (s *Store) SaveStates(states map[string]*alert.State) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bState)
		for id, st := range states {
			v, err := json.Marshal(st)
			if err != nil {
				return err
			}
			if err := b.Put([]byte(id), v); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) States() (map[string]*alert.State, error) {
	out := map[string]*alert.State{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bState).ForEach(func(k, v []byte) error {
			var st alert.State
			if json.Unmarshal(v, &st) == nil {
				out[string(k)] = &st
			}
			return nil
		})
	})
	return out, err
}

// Last returns the newest history entry for a check.
func (s *Store) Last(id string) (Entry, bool) {
	var e Entry
	var ok bool
	s.db.View(func(tx *bolt.Tx) error {
		if h := tx.Bucket(bHist).Bucket([]byte(id)); h != nil {
			if k, v := h.Cursor().Last(); k != nil {
				e, ok = decode(k, v), true
			}
		}
		return nil
	})
	return e, ok
}

// History returns entries since t, newest first, at most limit (0 = all).
func (s *Store) History(id string, since time.Time, limit int) ([]Entry, error) {
	var out []Entry
	err := s.db.View(func(tx *bolt.Tx) error {
		h := tx.Bucket(bHist).Bucket([]byte(id))
		if h == nil {
			return nil
		}
		c := h.Cursor()
		var min []byte
		if !since.IsZero() {
			min = key(since)
		}
		for k, v := c.Last(); k != nil && string(k) >= string(min); k, v = c.Prev() {
			out = append(out, decode(k, v))
			if limit > 0 && len(out) >= limit {
				break
			}
		}
		return nil
	})
	return out, err
}

// Prune drops history older than before, and history and state of checks no longer configured.
func (s *Store) Prune(before time.Time, keep map[string]bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		hist := tx.Bucket(bHist)
		var gone [][]byte
		err := hist.ForEach(func(name, _ []byte) error {
			if !keep[string(name)] {
				gone = append(gone, append([]byte(nil), name...))
				return nil
			}
			c := hist.Bucket(name).Cursor()
			max := key(before)
			for k, _ := c.First(); k != nil && string(k) < string(max); k, _ = c.First() {
				if err := c.Delete(); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, n := range gone {
			if err := hist.DeleteBucket(n); err != nil {
				return err
			}
		}
		st := tx.Bucket(bState)
		var stale [][]byte
		st.ForEach(func(k, _ []byte) error {
			if !keep[string(k)] {
				stale = append(stale, append([]byte(nil), k...))
			}
			return nil
		})
		for _, k := range stale {
			st.Delete(k)
		}
		return nil
	})
}

func (s *Store) Meta(k string) string {
	var v string
	s.db.View(func(tx *bolt.Tx) error {
		v = string(tx.Bucket(bMeta).Get([]byte(k)))
		return nil
	})
	return v
}

func (s *Store) SetMeta(k, v string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bMeta).Put([]byte(k), []byte(v)) })
}

// DailyWorst summarizes history as the worst status per local day, oldest first.
func DailyWorst(entries []Entry, days int, now time.Time) []status.Status {
	out := make([]status.Status, days)
	for i := range out {
		out[i] = status.Locked // no data
	}
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location()).AddDate(0, 0, -(days - 1))
	seen := make([]bool, days)
	for _, e := range entries {
		d := int(e.Time.In(now.Location()).Sub(start).Hours() / 24)
		if e.Time.Before(start) || d >= days {
			continue
		}
		if !seen[d] || e.Status.Rank() > out[d].Rank() {
			out[d], seen[d] = e.Status, true
		}
	}
	return out
}
