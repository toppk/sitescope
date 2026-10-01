// Package report is the JSON document an agent serves at /v1/report.
package report

import "time"

type Report struct {
	Host        string     `json:"host"`
	Time        time.Time  `json:"time"`
	UptimeSec   float64    `json:"uptimeSec"`
	Load        [3]float64 `json:"load"`
	CPUs        int        `json:"cpus"`
	Memory      Memory     `json:"memory"`
	Disks       []Disk     `json:"disks"`
	FailedUnits []string   `json:"failedUnits"`
	System      System     `json:"system"`
	WireGuard   []WGPeer   `json:"wireguard,omitempty"`
	Postfix     *Postfix   `json:"postfix,omitempty"`
	Knot        []Zone     `json:"knot,omitempty"`
	// Per-section collection errors, so one broken probe doesn't hide the rest.
	Errors map[string]string `json:"errors,omitempty"`
}

type Memory struct {
	TotalKB     uint64 `json:"totalKB"`
	AvailableKB uint64 `json:"availableKB"`
	SwapTotalKB uint64 `json:"swapTotalKB"`
	SwapFreeKB  uint64 `json:"swapFreeKB"`
}

type Disk struct {
	Mount      string  `json:"mount"`
	FSType     string  `json:"fsType"`
	TotalBytes uint64  `json:"totalBytes"`
	AvailBytes uint64  `json:"availBytes"`
	UsedPct    float64 `json:"usedPct"`
	InodesPct  float64 `json:"inodesPct"`
}

type System struct {
	Booted       string `json:"booted"`
	Current      string `json:"current"`
	RebootNeeded bool   `json:"rebootNeeded"`
	NixosVersion string `json:"nixosVersion"`
	// Nixpkgs revision date taken from the version string (YYYYMMDD).
	NixpkgsDate string `json:"nixpkgsDate,omitempty"`
}

type WGPeer struct {
	PublicKey string `json:"publicKey"`
	// Unix seconds of the latest handshake; 0 means never.
	LatestHandshake int64 `json:"latestHandshake"`
}

type Postfix struct {
	Messages     int     `json:"messages"`
	OldestAgeSec float64 `json:"oldestAgeSec"`
}

type Zone struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Serial uint32 `json:"serial"`
	// Seconds until a secondary zone expires; -1 when not applicable.
	ExpiresInSec int64 `json:"expiresInSec"`
}
