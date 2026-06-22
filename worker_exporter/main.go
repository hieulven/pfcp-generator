// worker_exporter — native per-worker Prometheus exporter (Go 1.23.2).
//
// Runs ON the worker node (NOT inside the DPDK app). Exposes what the kernel
// sees, which the in-app exporter cannot:
//
//   - CPU core frequency  -> /sys/devices/system/cpu/cpuN/cpufreq/scaling_cur_freq
//   - Per-socket UDP stats (drops, rx/tx queue) -> /proc/net/udp[6], filtered by
//     local port and, optionally, by owning process name, for a specific app.
//
// Everything is configurable through an INI file: the /metrics listen port, the
// core list, and one section per monitored socket. Pure stdlib, no external
// modules, so `go build` yields a single static binary with nothing to install.
//
// Usage:
//
//	worker_exporter [--config PATH] [--port N] [--bind ADDR] [--once]
//
//	--once   collect once, print to stdout, exit (handy for debugging / cron)
//
// Privileges:
//   - scaling_cur_freq is world-readable          -> no root needed.
//   - port-only socket matching (/proc/net/udp)   -> no root needed.
//   - comm= matching (socket -> process by name)  -> needs to read other
//     processes' /proc/<pid>/fd, i.e. root or CAP_DAC_READ_SEARCH.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const defaultConfig = "/etc/worker_exporter.conf"

var protoFile = map[string]string{
	"udp":  "/proc/net/udp",
	"udp6": "/proc/net/udp6",
	"tcp":  "/proc/net/tcp",
	"tcp6": "/proc/net/tcp6",
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type socketTarget struct {
	name  string
	proto string // udp | udp6 | tcp | tcp6
	port  int
	comm  string // optional process-name filter
}

type config struct {
	bind    string
	port    int
	cores   []int
	sockets []socketTarget
}

// iniFile is a tiny INI reader (sections, key=value, # / ; comments).
type iniFile struct {
	order    []string                     // section names in file order
	sections map[string]map[string]string // section -> key(lowercased) -> value
}

func parseINI(path string) (*iniFile, error) {
	f := &iniFile{sections: map[string]map[string]string{"": {}}}
	data, err := os.ReadFile(path)
	if err != nil {
		return f, err
	}
	cur := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := f.sections[cur]; !ok {
				f.sections[cur] = map[string]string{}
				f.order = append(f.order, cur)
			}
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		f.sections[cur][key] = val
	}
	return f, nil
}

func (f *iniFile) get(section, key, def string) string {
	if s, ok := f.sections[section]; ok {
		if v, ok := s[key]; ok {
			return v
		}
	}
	return def
}

func (f *iniFile) getInt(section, key string, def int) int {
	if v := f.get(section, key, ""); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func loadConfig(path string) *config {
	cfg := &config{bind: "0.0.0.0", port: 19200}
	f, err := parseINI(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v (using defaults)\n", err)
	}
	cfg.bind = f.get("exporter", "bind", cfg.bind)
	cfg.port = f.getInt("exporter", "port", cfg.port)
	cfg.cores = parseCores(f.get("cpufreq", "cores", ""))
	for _, sect := range f.order {
		if !strings.HasPrefix(sect, "socket:") {
			continue
		}
		name := strings.TrimSpace(sect[len("socket:"):])
		port := f.getInt(sect, "port", -1)
		if port < 0 {
			fmt.Fprintf(os.Stderr, "socket %q: missing/invalid port, skipping\n", name)
			continue
		}
		cfg.sockets = append(cfg.sockets, socketTarget{
			name:  name,
			proto: strings.ToLower(f.get(sect, "proto", "udp")),
			port:  port,
			comm:  strings.TrimSpace(f.get(sect, "comm", "")),
		})
	}
	return cfg
}

// parseCores turns "2-5,8,10" or "all" into a sorted, de-duplicated []int.
func parseCores(spec string) []int {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}
	if spec == "all" {
		var cores []int
		matches, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*")
		for _, m := range matches {
			base := filepath.Base(m) // cpuN
			if len(base) > 3 {
				if n, err := strconv.Atoi(base[3:]); err == nil {
					cores = append(cores, n)
				}
			}
		}
		sort.Ints(cores)
		return cores
	}
	seen := map[int]bool{}
	var cores []int
	add := func(n int) {
		if !seen[n] {
			seen[n] = true
			cores = append(cores, n)
		}
	}
	for _, tok := range strings.Split(spec, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if i := strings.Index(tok, "-"); i >= 0 {
			a, err1 := strconv.Atoi(strings.TrimSpace(tok[:i]))
			b, err2 := strconv.Atoi(strings.TrimSpace(tok[i+1:]))
			if err1 == nil && err2 == nil {
				for n := a; n <= b; n++ {
					add(n)
				}
			}
		} else if n, err := strconv.Atoi(tok); err == nil {
			add(n)
		}
	}
	sort.Ints(cores)
	return cores
}

// ---------------------------------------------------------------------------
// CPU frequency
// ---------------------------------------------------------------------------

type coreFreq struct {
	core int
	hz   uint64
}

func readCPUFreqs(cores []int) []coreFreq {
	var out []coreFreq
	for _, c := range cores {
		p := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", c)
		data, err := os.ReadFile(p)
		if err != nil {
			continue // offline core or no cpufreq driver
		}
		khz, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		if err != nil {
			continue
		}
		out = append(out, coreFreq{c, khz * 1000}) // sysfs is kHz -> Hz
	}
	return out
}

// ---------------------------------------------------------------------------
// Socket stats
// ---------------------------------------------------------------------------

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// pidsForComm returns PIDs whose /proc/<pid>/comm matches name (comm is
// truncated by the kernel to 15 chars).
func pidsForComm(name string) []string {
	target := name
	if len(target) > 15 {
		target = target[:15]
	}
	var pids []string
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return pids
	}
	for _, e := range entries {
		n := e.Name()
		if !isAllDigits(n) {
			continue
		}
		data, err := os.ReadFile("/proc/" + n + "/comm")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == target {
			pids = append(pids, n)
		}
	}
	return pids
}

// socketInodes returns the set of socket inode numbers held by the given PIDs.
func socketInodes(pids []string) map[uint64]bool {
	inodes := map[uint64]bool{}
	for _, pid := range pids {
		dir := "/proc/" + pid + "/fd"
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			link, err := os.Readlink(dir + "/" + e.Name())
			if err != nil {
				continue
			}
			if strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
				inoStr := link[len("socket:[") : len(link)-1]
				if ino, err := strconv.ParseUint(inoStr, 10, 64); err == nil {
					inodes[ino] = true
				}
			}
		}
	}
	return inodes
}

type netRow struct {
	port    int
	txQueue uint64
	rxQueue uint64
	inode   uint64
	drops   int64 // -1 when not applicable (tcp)
}

// parseNet parses /proc/net/{udp,udp6,tcp,tcp6}. drops is -1 for tcp (the
// kernel does not expose a per-socket tcp drop count there).
func parseNet(proto string) []netRow {
	var rows []netRow
	path, ok := protoFile[proto]
	if !ok {
		return rows
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return rows
	}
	isUDP := strings.HasPrefix(proto, "udp")
	for i, line := range strings.Split(string(data), "\n") {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 13 {
			continue
		}
		local := fields[1]
		colon := strings.LastIndex(local, ":")
		if colon < 0 {
			continue
		}
		port, err := strconv.ParseUint(local[colon+1:], 16, 32)
		if err != nil {
			continue
		}
		q := strings.SplitN(fields[4], ":", 2)
		if len(q) != 2 {
			continue
		}
		txq, err1 := strconv.ParseUint(q[0], 16, 64)
		rxq, err2 := strconv.ParseUint(q[1], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		drops := int64(-1)
		if isUDP {
			d, err := strconv.ParseInt(fields[12], 10, 64)
			if err != nil {
				continue
			}
			drops = d
		}
		rows = append(rows, netRow{int(port), txq, rxq, inode, drops})
	}
	return rows
}

type sockStat struct {
	name    string
	proto   string
	port    int
	count   int
	drops   int64 // -1 when not applicable
	rxQueue uint64
	txQueue uint64
}

func collectSockets(targets []socketTarget) []sockStat {
	netCache := map[string][]netRow{}
	inodeCache := map[string]map[uint64]bool{}
	var out []sockStat
	for _, t := range targets {
		rows, ok := netCache[t.proto]
		if !ok {
			rows = parseNet(t.proto)
			netCache[t.proto] = rows
		}
		var matched []netRow
		for _, r := range rows {
			if r.port == t.port {
				matched = append(matched, r)
			}
		}
		if t.comm != "" {
			inodes, ok := inodeCache[t.comm]
			if !ok {
				inodes = socketInodes(pidsForComm(t.comm))
				inodeCache[t.comm] = inodes
			}
			var filt []netRow
			for _, r := range matched {
				if inodes[r.inode] {
					filt = append(filt, r)
				}
			}
			matched = filt
		}
		isUDP := strings.HasPrefix(t.proto, "udp")
		drops := int64(-1)
		if isUDP {
			drops = 0
		}
		var rxq, txq uint64
		for _, r := range matched {
			if isUDP && r.drops >= 0 {
				drops += r.drops
			}
			rxq += r.rxQueue
			txq += r.txQueue
		}
		out = append(out, sockStat{t.name, t.proto, t.port, len(matched), drops, rxq, txq})
	}
	return out
}

// ---------------------------------------------------------------------------
// Rendering (Prometheus text exposition 0.0.4)
// ---------------------------------------------------------------------------

func escape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	return s
}

func render(cfg *config) string {
	var b strings.Builder

	b.WriteString("# HELP worker_cpu_scaling_cur_freq_hertz Current core frequency from cpufreq scaling_cur_freq.\n")
	b.WriteString("# TYPE worker_cpu_scaling_cur_freq_hertz gauge\n")
	for _, cf := range readCPUFreqs(cfg.cores) {
		fmt.Fprintf(&b, "worker_cpu_scaling_cur_freq_hertz{core=\"%d\"} %d\n", cf.core, cf.hz)
	}

	socks := collectSockets(cfg.sockets)
	lbl := func(s sockStat) string {
		return fmt.Sprintf("name=\"%s\",proto=\"%s\",port=\"%d\"", escape(s.name), escape(s.proto), s.port)
	}

	b.WriteString("# HELP worker_socket_drops_total Datagrams dropped by the kernel socket (UDP), summed across matching sockets.\n")
	b.WriteString("# TYPE worker_socket_drops_total counter\n")
	for _, s := range socks {
		if s.drops >= 0 {
			fmt.Fprintf(&b, "worker_socket_drops_total{%s} %d\n", lbl(s), s.drops)
		}
	}

	b.WriteString("# HELP worker_socket_rx_queue_bytes Bytes currently queued in the socket receive buffer.\n")
	b.WriteString("# TYPE worker_socket_rx_queue_bytes gauge\n")
	for _, s := range socks {
		fmt.Fprintf(&b, "worker_socket_rx_queue_bytes{%s} %d\n", lbl(s), s.rxQueue)
	}

	b.WriteString("# HELP worker_socket_tx_queue_bytes Bytes currently queued in the socket transmit buffer.\n")
	b.WriteString("# TYPE worker_socket_tx_queue_bytes gauge\n")
	for _, s := range socks {
		fmt.Fprintf(&b, "worker_socket_tx_queue_bytes{%s} %d\n", lbl(s), s.txQueue)
	}

	b.WriteString("# HELP worker_socket_count Kernel sockets matched for this target (SO_REUSEPORT fan-out / found check).\n")
	b.WriteString("# TYPE worker_socket_count gauge\n")
	for _, s := range socks {
		fmt.Fprintf(&b, "worker_socket_count{%s} %d\n", lbl(s), s.count)
	}

	return b.String()
}

// ---------------------------------------------------------------------------
// main / HTTP
// ---------------------------------------------------------------------------

func main() {
	configPath := flag.String("config", defaultConfig, "path to INI config")
	portFlag := flag.Int("port", 0, "override [exporter] port")
	bindFlag := flag.String("bind", "", "override [exporter] bind address")
	once := flag.Bool("once", false, "print metrics once and exit")
	flag.Parse()

	cfg := loadConfig(*configPath)
	if *portFlag != 0 {
		cfg.port = *portFlag
	}
	if *bindFlag != "" {
		cfg.bind = *bindFlag
	}

	if *once {
		fmt.Print(render(cfg))
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		io.WriteString(w, render(cfg))
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok\n")
	})

	addr := fmt.Sprintf("%s:%d", cfg.bind, cfg.port)
	names := make([]string, 0, len(cfg.sockets))
	for _, s := range cfg.sockets {
		names = append(names, s.name)
	}
	fmt.Fprintf(os.Stderr, "worker_exporter listening on %s (cores=%v, sockets=%v)\n", addr, cfg.cores, names)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}
