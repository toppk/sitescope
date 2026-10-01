// Package status defines check severities and warn/crit thresholds.
package status

import (
	"encoding/json"
	"fmt"
)

type Status int8

const (
	Unknown Status = iota
	OK
	Warn
	Crit
	Locked
)

var statusNames = [...]string{"unknown", "ok", "warn", "crit", "locked"}

func (s Status) String() string {
	if s < 0 || int(s) >= len(statusNames) {
		return "invalid"
	}
	return statusNames[s]
}

func ParseStatus(v string) (Status, error) {
	for i, n := range statusNames {
		if n == v {
			return Status(i), nil
		}
	}
	return Unknown, fmt.Errorf("unknown status %q", v)
}

func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

func (s *Status) UnmarshalJSON(b []byte) error {
	var v string
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	p, err := ParseStatus(v)
	*s = p
	return err
}

// Rank orders statuses by how bad they are; locked ranks with ok so it never raises an alarm.
func (s Status) Rank() int {
	switch s {
	case Crit:
		return 3
	case Warn:
		return 2
	case Unknown:
		return 1
	}
	return 0
}

func Worst(ss ...Status) Status {
	w := OK
	for _, s := range ss {
		if s.Rank() > w.Rank() {
			w = s
		}
	}
	return w
}

// Alerting reports whether a status is one we notify about (as opposed to unknown/locked).
func (s Status) Alerting() bool { return s == OK || s == Warn || s == Crit }

// Threshold is a warn/crit pair; a zero bound is disabled.
type Threshold struct {
	Warn float64 `json:"warn"`
	Crit float64 `json:"crit"`
}

// Above rates v where larger is worse (usage, age, latency).
func (t Threshold) Above(v float64) Status {
	switch {
	case t.Crit != 0 && v >= t.Crit:
		return Crit
	case t.Warn != 0 && v >= t.Warn:
		return Warn
	}
	return OK
}

// Below rates v where smaller is worse (days left).
func (t Threshold) Below(v float64) Status {
	switch {
	case t.Crit != 0 && v <= t.Crit:
		return Crit
	case t.Warn != 0 && v <= t.Warn:
		return Warn
	}
	return OK
}

// Or returns t with unset bounds taken from def.
func (t Threshold) Or(def Threshold) Threshold {
	if t.Warn == 0 {
		t.Warn = def.Warn
	}
	if t.Crit == 0 {
		t.Crit = def.Crit
	}
	return t
}
