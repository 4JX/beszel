package agent

import (
	"bufio"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/henrygd/beszel/internal/entities/system"
	"github.com/moby/sys/mountinfo"
	"github.com/shirou/gopsutil/v4/disk"
)

type diskSpec struct {
	Identifier, Alias, IoOverride string
}

type mountRec struct {
	Path, Source, SourceReal string
	Major, Minor             int
}

type trackedDisk struct {
	UsagePath string // Path passed to disk.Usage()
	IoDevice  string // Canonical IOCounters key (e.g., "sda")
	Stats     *system.FsStats
}

type ioSample struct {
	read, write uint64
	at          time.Time
}

// initializeDiskInfo snapshots the system state and maps user identifiers to tracking targets.
func (a *Agent) initializeDiskInfo() {
	counters, err := disk.IOCounters()
	if err != nil {
		slog.Warn("Error getting initial disk I/O counters", "err", err)
		counters = make(map[string]disk.IOCountersStat)
	}
	ioAliases := buildIOAliasMap(counters)
	diskstats := getDiskstatsMap()
	mounts := discoverMounts()

	rootPath := chooseRootPath(mounts)
	specs := parseDiskSpecs(os.Getenv("DISKS"))
	if !hasRootSpec(specs, rootPath) {
		specs = append([]diskSpec{{Identifier: rootPath, Alias: "root"}}, specs...)
	}

	// Reset agent state
	a.disks = make([]*trackedDisk, 0, len(specs))
	a.byIODevice = make(map[string][]*trackedDisk)
	a.prevIO = make(map[uint16]map[string]ioSample)
	a.ioDevices = a.ioDevices[:0]

	seenUsage := make(map[string]struct{}, len(specs))
	rootResolved := false

	for _, spec := range specs {
		usagePath, mRec, found := resolveToMount(spec.Identifier, mounts)
		if usagePath == "" {
			continue
		}

		// Dedupe using normalized keys to handle trailing slashes and Windows casing
		usageKey := normalizePathKey(usagePath)
		if _, exists := seenUsage[usageKey]; exists {
			slog.Warn("Duplicate disk ignored", "path", usagePath, "identifier", spec.Identifier)
			continue
		}
		seenUsage[usageKey] = struct{}{}

		isRoot := samePath(usagePath, rootPath) || strings.EqualFold(spec.Alias, "root")
		name := spec.Alias
		if name == "" {
			if isRoot {
				name = "root"
			} else {
				name = filepath.Base(filepath.Clean(usagePath))
			}
		}

		// Candidate resolution: Override > Kernel Name > Symlink > Source > Identifier
		candidates := make([]string, 0, 6)
		if spec.IoOverride != "" {
			candidates = append(candidates, spec.IoOverride)
		}
		if found {
			candidates = append(candidates,
				diskstats[[2]int{mRec.Major, mRec.Minor}],
				mRec.SourceReal, parentDiskName(mRec.SourceReal),
				mRec.Source, parentDiskName(mRec.Source),
			)
		}
		// Only use identifier as an I/O candidate if it's a device path or a simple token (not an absolute dir)
		if isDevicePath(spec.Identifier) || !filepath.IsAbs(spec.Identifier) {
			candidates = append(candidates, spec.Identifier)
			if isDevicePath(spec.Identifier) {
				candidates = append(candidates, parentDiskName(spec.Identifier))
			}
		}

		ioDev, ok := lookupIODevice(candidates, ioAliases)
		if !ok {
			slog.Warn("Disk configured without I/O device", "identifier", spec.Identifier, "usagePath", usagePath, "candidates", candidates)
		}

		td := &trackedDisk{
			UsagePath: usagePath,
			IoDevice:  ioDev,
			Stats:     &system.FsStats{Name: name, Mountpoint: usagePath, Root: isRoot},
		}

		a.disks = append(a.disks, td)
		if ok {
			a.byIODevice[ioDev] = append(a.byIODevice[ioDev], td)
		}
		if isRoot {
			rootResolved = true
		}
	}

	// Final root safety fallback
	if !rootResolved {
		slog.Warn("No root entry resolved; adding usage-only root fallback", "path", rootPath)
		a.disks = append(a.disks, &trackedDisk{
			UsagePath: rootPath,
			Stats:     &system.FsStats{Name: "root", Mountpoint: rootPath, Root: true},
		})
	}

	// Build cached list of unique I/O devices for the sampling pass
	for dev := range a.byIODevice {
		a.ioDevices = append(a.ioDevices, dev)
	}
	sort.Strings(a.ioDevices)
}

// updateDiskUsage updates filesystem usage stats.
// Root is always refreshed; non-root filesystems can be cached to avoid waking disks.
func (a *Agent) updateDiskUsage(systemStats *system.Stats) {
	cacheExtraFs := a.diskUsageCacheDuration > 0 &&
		!a.lastDiskUsageUpdate.IsZero() &&
		time.Since(a.lastDiskUsageUpdate) < a.diskUsageCacheDuration

	for _, tracked := range a.disks {
		if tracked == nil || tracked.Stats == nil {
			continue
		}
		stats := tracked.Stats

		if cacheExtraFs && !stats.Root {
			continue
		}

		d, err := disk.Usage(tracked.UsagePath)
		if err != nil {
			slog.Error("Error getting disk usage", "path", tracked.UsagePath, "err", err)
			stats.DiskTotal = 0
			stats.DiskUsed = 0
			stats.DiskReadPs = 0
			stats.DiskWritePs = 0
			stats.DiskReadBytes = 0
			stats.DiskWriteBytes = 0
			continue
		}

		stats.DiskTotal = bytesToGigabytes(d.Total)
		stats.DiskUsed = bytesToGigabytes(d.Used)

		if stats.Root {
			systemStats.DiskTotal = stats.DiskTotal
			systemStats.DiskUsed = stats.DiskUsed
			systemStats.DiskPct = twoDecimals(d.UsedPercent)
		}
	}

	if !cacheExtraFs {
		a.lastDiskUsageUpdate = time.Now()
	}
}

// updateDiskIo calculates throughput rates per block device and updates all sharing filesystems.
func (a *Agent) updateDiskIo(interval uint16, systemStats *system.Stats) {
	if len(a.ioDevices) == 0 {
		return
	}
	counters, err := disk.IOCounters(a.ioDevices...)
	if err != nil {
		slog.Error("Error getting disk I/O counters", "err", err)
		return
	}

	now := time.Now()
	if a.prevIO[interval] == nil {
		a.prevIO[interval] = make(map[string]ioSample, len(a.ioDevices))
	}
	prevMap := a.prevIO[interval]

	for _, dev := range a.ioDevices {
		c, ok := counters[dev]
		if !ok {
			continue
		}

		curr := ioSample{read: c.ReadBytes, write: c.WriteBytes, at: now}
		prev, hasPrev := prevMap[dev]
		prevMap[dev] = curr

		// Guard: Need history, significant time gap, and no counter underflow/reboots
		if !hasPrev || prev.at.IsZero() || now.Sub(prev.at) < 100*time.Millisecond ||
			curr.read < prev.read || curr.write < prev.write {
			continue
		}

		ms := uint64(now.Sub(prev.at).Milliseconds())
		if ms == 0 {
			continue
		}

		readBps := (curr.read - prev.read) * 1000 / ms
		writeBps := (curr.write - prev.write) * 1000 / ms
		readMBps, writeMBps := bytesToMegabytes(float64(readBps)), bytesToMegabytes(float64(writeBps))

		if readMBps > 50_000 || writeMBps > 50_000 { // Sanity cap
			continue
		}

		for _, td := range a.byIODevice[dev] {
			td.Stats.DiskReadPs, td.Stats.DiskWritePs = readMBps, writeMBps
			td.Stats.DiskReadBytes, td.Stats.DiskWriteBytes = readBps, writeBps
			if td.Stats.Root {
				systemStats.DiskReadPs, systemStats.DiskWritePs = readMBps, writeMBps
				systemStats.DiskIO[0], systemStats.DiskIO[1] = readBps, writeBps
			}
		}
	}
}

// discoverMounts returns normalized mount records.
// Linux uses mountinfo; other platforms fall back to disk.Partitions(false).
func discoverMounts() (records []mountRec) {
	if runtime.GOOS == "linux" {
		if mounts, err := mountinfo.GetMounts(nil); err == nil {
			for _, m := range mounts {
				realSrc, _ := filepath.EvalSymlinks(m.Source)
				if realSrc == "" {
					realSrc = m.Source
				}
				records = append(records, mountRec{Path: m.Mountpoint, Source: m.Source, SourceReal: realSrc, Major: m.Major, Minor: m.Minor})
			}
			return
		} else {
			slog.Warn("Error getting mountinfo; falling back to disk partitions", "err", err)
		}
	}
	if parts, err := disk.Partitions(false); err == nil {
		for _, p := range parts {
			src := p.Device
			if runtime.GOOS == "windows" {
				src = strings.TrimSuffix(src, `\`)
			}
			records = append(records, mountRec{Path: p.Mountpoint, Source: src, SourceReal: src})
		}
	} else {
		slog.Warn("Error getting disk partitions", "err", err)
	}
	return
}

// resolveToMount resolves an identifier to its best usage target and mount record.
func resolveToMount(id string, mounts []mountRec) (string, mountRec, bool) {
	norm := normalizePathKey(id)
	if norm == "" {
		return "", mountRec{}, false
	}

	// 1. Exact matches
	for _, m := range mounts {
		if samePath(m.Path, norm) || samePath(m.Source, norm) || samePath(m.SourceReal, norm) {
			return m.Path, m, true
		}
	}

	// Device paths should not be resolved via mount-prefix heuristics.
	if !filepath.IsAbs(id) || isDevicePath(id) {
		return "", mountRec{}, false
	}

	// 2. Subpath resolution (Deepest parent mount)
	bestIdx, bestLen := -1, -1
	for i, m := range mounts {
		if hasMountPrefix(norm, m.Path) {
			if l := len(normalizePathKey(m.Path)); l > bestLen {
				bestIdx, bestLen = i, l
			}
		}
	}
	if bestIdx >= 0 {
		return mounts[bestIdx].Path, mounts[bestIdx], true
	}

	// 3. Absolute path usage-only fallback
	cleaned := filepath.Clean(id)
	if _, err := disk.Usage(cleaned); err == nil {
		return cleaned, mountRec{}, false
	}

	return "", mountRec{}, false
}

func lookupIODevice(candidates []string, aliases map[string]string) (string, bool) {
	seen := make(map[string]struct{})
	for _, c := range candidates {
		norm := normalizeDeviceName(c)
		if _, exists := seen[norm]; norm == "" || exists {
			continue
		}
		seen[norm] = struct{}{}
		if key, ok := aliases[norm]; ok {
			return key, true
		}
	}
	return "", false
}

// --- Data Normalization Helpers ---

func buildIOAliasMap(counters map[string]disk.IOCountersStat) map[string]string {
	out := make(map[string]string, len(counters)*3)
	for key, stat := range counters {
		for _, raw := range []string{key, stat.Name, stat.Label} {
			if norm := normalizeDeviceName(raw); norm != "" {
				if _, ok := out[norm]; !ok {
					out[norm] = key
				}
			}
		}
	}
	return out
}

func getDiskstatsMap() map[[2]int]string {
	m := make(map[[2]int]string)
	if runtime.GOOS != "linux" {
		return m
	}

	f, err := os.Open("/proc/diskstats")
	if err != nil {
		return m
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		maj, err1 := strconv.Atoi(fields[0])
		min, err2 := strconv.Atoi(fields[1])
		if err1 == nil && err2 == nil {
			m[[2]int{maj, min}] = fields[2]
		}
	}
	return m
}

func chooseRootPath(mounts []mountRec) string {
	if runtime.GOOS == "linux" {
		for _, p := range []string{"/sysroot", "/"} {
			for _, m := range mounts {
				if samePath(m.Path, p) {
					return p
				}
			}
		}
		for _, p := range []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"} {
			for _, m := range mounts {
				if samePath(m.Path, p) &&
					(strings.HasPrefix(m.Source, "/dev/") || strings.HasPrefix(m.SourceReal, "/dev/")) {
					return p
				}
			}
		}
		return "/"
	}

	for _, m := range mounts {
		if samePath(m.Path, "/") || samePath(m.Path, `C:\`) {
			return m.Path
		}
	}
	if len(mounts) > 0 && mounts[0].Path != "" {
		return mounts[0].Path
	}
	return "/"
}

func normalizePathKey(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	p := filepath.Clean(path)
	if runtime.GOOS == "windows" {
		return strings.ToLower(strings.TrimSuffix(p, `\`))
	}
	return p
}

func samePath(a, b string) bool { return normalizePathKey(a) == normalizePathKey(b) }

func hasMountPrefix(path, mount string) bool {
	p, m := normalizePathKey(path), normalizePathKey(mount)
	if p == m {
		return true
	}
	if m == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, m+string(filepath.Separator))
}

func normalizeDeviceName(v string) string {
	base := filepath.Base(strings.TrimSpace(v))
	if base == "." || base == "/" || base == "\\" {
		return ""
	}
	return base
}

func parentDiskName(v string) string {
	base := normalizeDeviceName(v)
	parent := strings.TrimRight(base, "0123456789")
	if b, ok := strings.CutSuffix(parent, "p"); ok {
		parent = b
	}
	if parent == "" || parent == base {
		return ""
	}
	return parent
}

func isDevicePath(p string) bool {
	return runtime.GOOS != "windows" && strings.HasPrefix(filepath.Clean(p), "/dev/")
}

func parseDiskSpecs(env string) (specs []diskSpec) {
	env = strings.TrimSpace(env)
	if env == "" {
		return nil
	}

	seen := make(map[string]int)
	for i, raw := range strings.Split(env, ",") {
		parts := strings.SplitN(strings.TrimSpace(raw), "|", 3)
		id := strings.TrimSpace(parts[0])
		if id == "" {
			continue
		}
		if first, ok := seen[id]; ok {
			slog.Warn("Duplicate DISKS identifier; keeping first occurrence", "identifier", id, "firstIndex", first, "duplicateIndex", i)
			continue
		}
		seen[id] = i

		spec := diskSpec{Identifier: id}
		if len(parts) > 1 {
			spec.Alias = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			spec.IoOverride = strings.TrimSpace(parts[2])
		}
		specs = append(specs, spec)
	}
	return
}

func hasRootSpec(specs []diskSpec, rootPath string) bool {
	for _, s := range specs {
		if samePath(s.Identifier, rootPath) || s.Identifier == "/" || strings.EqualFold(s.Alias, "root") {
			return true
		}
	}
	return false
}
