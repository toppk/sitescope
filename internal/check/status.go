// Package check holds check definitions, results and the probe implementations.
package check

import "github.com/toppk/sitescope/internal/status"

type (
	Status    = status.Status
	Threshold = status.Threshold
)

const (
	Unknown = status.Unknown
	OK      = status.OK
	Warn    = status.Warn
	Crit    = status.Crit
	Locked  = status.Locked
)

var Worst = status.Worst
