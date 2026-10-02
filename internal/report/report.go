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
	Counters    *Counters  `json:"counters,omitempty"`
	Units       []UnitMem  `json:"units,omitempty"`
	// Per-section collection errors, so one broken probe doesn't hide the rest.
	Errors map[string]string `json:"errors,omitempty"`
}

type Memory struct {
	TotalKB     uint64 `json:"totalKB"`
	AvailableKB uint64 `json:"availableKB"`
	FreeKB      uint64 `json:"freeKB"`
	BuffersKB   uint64 `json:"buffersKB"`
	CachedKB    uint64 `json:"cachedKB"`
	ShmemKB     uint64 `json:"shmemKB"`
	DirtyKB     uint64 `json:"dirtyKB"`
	SwapTotalKB uint64 `json:"swapTotalKB"`
	SwapFreeKB  uint64 `json:"swapFreeKB"`
}

// Counters are cumulative since boot; the hub turns two reports into rates.
type Counters struct {
	BootTime int64          `json:"bootTime"`
	CPU      []CPU          `json:"cpu"` // per CPU, in order
	Pressure map[string]PSI `json:"pressure,omitempty"`
	VM       VMStat         `json:"vmstat"`
	Disks    []DiskIO       `json:"disks"`
	Net      []NetIO        `json:"net"`
}

// CPU is time spent per mode, in seconds.
type CPU struct {
	User    float64 `json:"user"`
	Nice    float64 `json:"nice"`
	System  float64 `json:"system"`
	Idle    float64 `json:"idle"`
	IOWait  float64 `json:"iowait"`
	IRQ     float64 `json:"irq"`
	SoftIRQ float64 `json:"softirq"`
	Steal   float64 `json:"steal"`
}

// PSI is one /proc/pressure file; totals in microseconds, averages in percent.
type PSI struct {
	SomeTotalUS uint64  `json:"someTotalUs"`
	FullTotalUS uint64  `json:"fullTotalUs"`
	SomeAvg60   float64 `json:"someAvg60"`
	FullAvg60   float64 `json:"fullAvg60"`
}

type VMStat struct {
	OOMKill    uint64 `json:"oomKill"`
	PswpIn     uint64 `json:"pswpin"`
	PswpOut    uint64 `json:"pswpout"`
	PgMajFault uint64 `json:"pgmajfault"`
}

type DiskIO struct {
	Device       string `json:"device"`
	Reads        uint64 `json:"reads"`
	Writes       uint64 `json:"writes"`
	ReadBytes    uint64 `json:"readBytes"`
	WrittenBytes uint64 `json:"writtenBytes"`
	IOTimeMS     uint64 `json:"ioTimeMs"`
}

type NetIO struct {
	Device  string `json:"device"`
	RxBytes uint64 `json:"rxBytes"`
	TxBytes uint64 `json:"txBytes"`
	RxErrs  uint64 `json:"rxErrs"`
	TxErrs  uint64 `json:"txErrs"`
	RxDrop  uint64 `json:"rxDrop"`
	TxDrop  uint64 `json:"txDrop"`
}

// UnitMem is a service's cgroup memory; MaxBytes is 0 without a MemoryMax.
type UnitMem struct {
	Unit     string `json:"unit"`
	Bytes    uint64 `json:"bytes"`
	MaxBytes uint64 `json:"maxBytes,omitempty"`
}

type Disk struct {
	Device     string  `json:"device"`
	Mount      string  `json:"mount"`
	FSType     string  `json:"fsType"`
	TotalBytes uint64  `json:"totalBytes"`
	AvailBytes uint64  `json:"availBytes"`
	UsedPct    float64 `json:"usedPct"`
	InodesPct  float64 `json:"inodesPct"`
	Files      uint64  `json:"files"`
	FilesFree  uint64  `json:"filesFree"`
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
	LatestHandshake int64  `json:"latestHandshake"`
	RxBytes         uint64 `json:"rxBytes"`
	TxBytes         uint64 `json:"txBytes"`
}

type Postfix struct {
	Messages     int            `json:"messages"`
	Queues       map[string]int `json:"queues,omitempty"` // messages per queue name
	OldestAgeSec float64        `json:"oldestAgeSec"`
}

type Zone struct {
	Name   string `json:"name"`
	Role   string `json:"role"`
	Serial uint32 `json:"serial"`
	// Seconds until a secondary zone expires; -1 when not applicable.
	ExpiresInSec int64 `json:"expiresInSec"`
}
