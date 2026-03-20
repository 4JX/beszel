package agent

import (
	"bufio"
	"log/slog"
	"os"
	pathpkg "path"
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

var (
	diskUsageFn      = disk.Usage
	diskIOCountersFn = disk.IOCounters
	discoverMountsFn = discoverMounts
)

type diskSpec struct {
	Identifier string
	Alias      string
	IoOverride string
}

type mountRec struct {
	Path       string
	Source     string
	SourceReal string
	MajorMinor string
	Root       bool
}

type trackedDisk struct {
	Key        string
	UsagePath  string
	IOKey      string
	Resolution string
	Stats      *system.FsStats
}

type ioSample struct {
	read  uint64
	write uint64
	at    time.Time
}

type ioIndex struct {
	byAlias      map[string]string
	byMajorMinor map[string]string
}

// initializeDiskInfo discovers monitored filesystems and optionally binds them to disk I/O counters.
func (a *Agent) initializeDiskInfo() {
	counters, err := diskIOCountersFn()
	if err != nil {
		slog.Warn("Error getting initial disk I/O counters", "err", err)
		counters = make(map[string]disk.IOCountersStat)
	}

	osName := runtime.GOOS
	mounts := discoverMountsFn()
	rootPath := chooseRootPath(osName, mounts)
	specs := parseDiskSpecs(os.Getenv("DISKS"))
	if !hasRootSpec(osName, specs, rootPath) {
		specs = append([]diskSpec{{Identifier: rootPath, Alias: "root"}}, specs...)
	}

	targets := materializeTrackedDisks(osName, mounts, rootPath, specs, buildIOIndex(counters, getDiskstatsMap()))
	if !hasRootTarget(targets) {
		slog.Warn("No root entry resolved; adding usage-only root fallback", "path", rootPath)
		targets = append(targets, &trackedDisk{
			Key:        normalizePath(osName, rootPath),
			UsagePath:  rootPath,
			Resolution: "usage_only",
			Stats: &system.FsStats{
				Name:       "root",
				Mountpoint: rootPath,
				Root:       true,
			},
		})
	}

	a.disks = targets
	a.byIODevice = make(map[string][]*trackedDisk, len(targets))
	a.prevIO = make(map[uint16]map[string]ioSample)
	a.ioDevices = a.ioDevices[:0]

	for _, target := range a.disks {
		if target.IOKey == "" {
			continue
		}
		a.byIODevice[target.IOKey] = append(a.byIODevice[target.IOKey], target)
	}
	for ioKey := range a.byIODevice {
		a.ioDevices = append(a.ioDevices, ioKey)
	}
	sort.Strings(a.ioDevices)
	a.initializeDiskIoTotals(counters)
}

func materializeTrackedDisks(osName string, mounts []mountRec, rootPath string, specs []diskSpec, idx ioIndex) []*trackedDisk {
	seenUsage := make(map[string]struct{}, len(specs))
	targets := make([]*trackedDisk, 0, len(specs))

	for _, spec := range sanitizeDiskSpecs(osName, specs, rootPath) {
		mount, ok := resolveMount(osName, spec.Identifier, mounts)
		if !ok || mount.Path == "" {
			continue
		}

		usageKey := normalizePath(osName, mount.Path)
		if _, exists := seenUsage[usageKey]; exists {
			slog.Warn("Duplicate disk ignored", "identifier", spec.Identifier, "path", mount.Path)
			continue
		}
		seenUsage[usageKey] = struct{}{}

		isRoot := mount.Root || samePath(osName, mount.Path, rootPath) || strings.EqualFold(spec.Alias, "root")
		name := spec.Alias
		if name == "" {
			if isRoot {
				name = "root"
			} else {
				name = filepath.Base(filepath.Clean(mount.Path))
			}
		}

		ioKey, rule := bindMountIO(osName, mount, spec, idx)
		targets = append(targets, &trackedDisk{
			Key:        usageKey,
			UsagePath:  mount.Path,
			IOKey:      ioKey,
			Resolution: rule,
			Stats: &system.FsStats{
				Name:       name,
				Mountpoint: mount.Path,
				Root:       isRoot,
			},
		})
	}

	return pruneRootMirrors(targets)
}

func sanitizeDiskSpecs(osName string, specs []diskSpec, rootPath string) []diskSpec {
	out := make([]diskSpec, 0, len(specs)+1)
	seen := make(map[string]struct{}, len(specs))
	rootPresent := false

	for _, spec := range specs {
		spec.Identifier = strings.TrimSpace(spec.Identifier)
		if spec.Identifier == "" {
			continue
		}
		key := normalizePath(osName, spec.Identifier)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, spec)
		if samePath(osName, spec.Identifier, rootPath) || strings.EqualFold(spec.Alias, "root") {
			rootPresent = true
		}
	}

	if !rootPresent && rootPath != "" {
		out = append([]diskSpec{{Identifier: rootPath, Alias: "root"}}, out...)
	}
	return out
}

func hasRootTarget(targets []*trackedDisk) bool {
	for _, target := range targets {
		if target != nil && target.Stats != nil && target.Stats.Root {
			return true
		}
	}
	return false
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

		d, err := diskUsageFn(tracked.UsagePath)
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

// updateDiskIo calculates throughput rates per bound I/O source and updates all sharing filesystems.
func (a *Agent) updateDiskIo(interval uint16, systemStats *system.Stats) {
	if len(a.ioDevices) == 0 {
		return
	}

	counters, err := diskIOCountersFn(a.ioDevices...)
	if err != nil {
		slog.Error("Error getting disk I/O counters", "err", err)
		return
	}

	now := time.Now()
	if a.prevIO[interval] == nil {
		a.prevIO[interval] = make(map[string]ioSample, len(a.ioDevices))
	}
	prevMap := a.prevIO[interval]

	for _, ioKey := range a.ioDevices {
		counter, ok := counters[ioKey]
		if !ok {
			continue
		}

		curr := ioSample{read: counter.ReadBytes, write: counter.WriteBytes, at: now}
		prev, hasPrev := prevMap[ioKey]
		prevMap[ioKey] = curr

		for _, target := range a.byIODevice[ioKey] {
			target.Stats.TotalRead = counter.ReadBytes
			target.Stats.TotalWrite = counter.WriteBytes
			target.Stats.Time = now
		}

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
		readMBps := bytesToMegabytes(float64(readBps))
		writeMBps := bytesToMegabytes(float64(writeBps))
		if readMBps > 50_000 || writeMBps > 50_000 {
			continue
		}

		for _, target := range a.byIODevice[ioKey] {
			target.Stats.DiskReadPs = readMBps
			target.Stats.DiskWritePs = writeMBps
			target.Stats.DiskReadBytes = readBps
			target.Stats.DiskWriteBytes = writeBps
			if target.Stats.Root {
				systemStats.DiskReadPs = readMBps
				systemStats.DiskWritePs = writeMBps
				systemStats.DiskIO[0] = readBps
				systemStats.DiskIO[1] = writeBps
			}
		}
	}
}

func (a *Agent) initializeDiskIoTotals(counters map[string]disk.IOCountersStat) {
	now := time.Now()
	for _, target := range a.disks {
		if target == nil || target.Stats == nil || target.IOKey == "" {
			continue
		}
		counter, ok := counters[target.IOKey]
		if !ok {
			continue
		}
		target.Stats.TotalRead = counter.ReadBytes
		target.Stats.TotalWrite = counter.WriteBytes
		target.Stats.Time = now
	}
}

// discoverMounts returns normalized mount records.
// Linux uses mountinfo; other platforms fall back to disk.Partitions(false).
func discoverMounts() []mountRec {
	osName := runtime.GOOS
	records := make([]mountRec, 0)

	if osName == "linux" {
		mounts, err := mountinfo.GetMounts(nil)
		if err == nil {
			records = make([]mountRec, 0, len(mounts))
			for _, mount := range mounts {
				sourceReal := mount.Source
				if real, err := filepath.EvalSymlinks(mount.Source); err == nil && real != "" {
					sourceReal = real
				}
				records = append(records, mountRec{
					Path:       mount.Mountpoint,
					Source:     mount.Source,
					SourceReal: sourceReal,
					MajorMinor: strconv.Itoa(mount.Major) + ":" + strconv.Itoa(mount.Minor),
				})
			}
			return records
		}
		slog.Warn("Error getting mountinfo; falling back to disk partitions", "err", err)
	}

	partitions, err := disk.Partitions(false)
	if err != nil {
		slog.Warn("Error getting disk partitions", "err", err)
		return records
	}

	records = make([]mountRec, 0, len(partitions))
	for _, part := range partitions {
		source := part.Device
		if osName == "windows" {
			source = strings.TrimRight(source, `\`)
		}
		records = append(records, mountRec{
			Path:       part.Mountpoint,
			Source:     source,
			SourceReal: source,
		})
	}
	return records
}

func resolveMount(osName, identifier string, mounts []mountRec) (mountRec, bool) {
	normIdentifier := normalizePath(osName, identifier)
	if normIdentifier == "" {
		return mountRec{}, false
	}

	for _, mount := range mounts {
		if samePath(osName, mount.Path, identifier) ||
			samePath(osName, mount.Source, identifier) ||
			samePath(osName, mount.SourceReal, identifier) {
			return mount, true
		}
	}

	if !isAbsPath(osName, identifier) || isDevicePath(osName, identifier) {
		return mountRec{}, false
	}

	bestIndex := -1
	bestLen := -1
	for i, mount := range mounts {
		if hasMountPrefix(osName, identifier, mount.Path) {
			if l := len(normalizePath(osName, mount.Path)); l > bestLen {
				bestIndex = i
				bestLen = l
			}
		}
	}
	if bestIndex >= 0 {
		return mounts[bestIndex], true
	}

	cleaned := normalizePath(osName, identifier)
	if _, err := diskUsageFn(cleaned); err == nil {
		return mountRec{Path: cleaned, Source: cleaned, SourceReal: cleaned}, true
	}
	return mountRec{}, false
}

func bindMountIO(osName string, mount mountRec, spec diskSpec, idx ioIndex) (string, string) {
	if spec.IoOverride != "" {
		if ioKey, ok := idx.byAlias[normalizeDeviceID(spec.IoOverride)]; ok {
			return ioKey, "explicit_override"
		}
		slog.Warn("Disk I/O override did not match any counter", "identifier", spec.Identifier, "override", spec.IoOverride)
	}

	switch osName {
	case "linux":
		if mount.MajorMinor != "" {
			if ioKey, ok := idx.byMajorMinor[mount.MajorMinor]; ok {
				return ioKey, "linux_major_minor"
			}
		}
		if ioKey, ok := idx.byAlias[normalizeDeviceID(mount.SourceReal)]; ok {
			return ioKey, "linux_source_real"
		}
		if ioKey, ok := idx.byAlias[normalizeDeviceID(mount.Source)]; ok {
			return ioKey, "linux_source"
		}
		if parent := parentDeviceName(mount.SourceReal); parent != "" {
			if ioKey, ok := idx.byAlias[parent]; ok {
				return ioKey, "linux_parent"
			}
		}
		if parent := parentDeviceName(mount.Source); parent != "" {
			if ioKey, ok := idx.byAlias[parent]; ok {
				return ioKey, "linux_parent"
			}
		}
	case "freebsd":
		if ioKey, ok := idx.byAlias[normalizeDeviceID(mount.SourceReal)]; ok {
			return ioKey, "freebsd_source"
		}
		if parent := parentDeviceName(mount.SourceReal); parent != "" {
			if ioKey, ok := idx.byAlias[parent]; ok {
				return ioKey, "freebsd_parent"
			}
		}
	case "windows":
		if ioKey, ok := idx.byAlias[normalizeDeviceID(mount.SourceReal)]; ok {
			return ioKey, "windows_drive"
		}
		if ioKey, ok := idx.byAlias[normalizeDeviceID(mount.Path)]; ok {
			return ioKey, "windows_drive"
		}
	case "darwin":
		if ioKey, ok := idx.byAlias[normalizeDeviceID(mount.SourceReal)]; ok {
			return ioKey, "darwin_source"
		}
		if parent := parentDeviceName(mount.SourceReal); parent != "" {
			if ioKey, ok := idx.byAlias[parent]; ok {
				return ioKey, "darwin_parent"
			}
		}
	}

	return "", "usage_only"
}

func buildIOIndex(counters map[string]disk.IOCountersStat, diskstats map[string]string) ioIndex {
	idx := ioIndex{
		byAlias:      make(map[string]string, len(counters)*4),
		byMajorMinor: make(map[string]string, len(diskstats)),
	}

	for key, stat := range counters {
		for _, raw := range []string{key, stat.Name, stat.Label} {
			norm := normalizeDeviceID(raw)
			if norm == "" {
				continue
			}
			if _, exists := idx.byAlias[norm]; !exists {
				idx.byAlias[norm] = key
			}
		}
	}

	for majorMinor, kernelName := range diskstats {
		if ioKey, ok := idx.byAlias[normalizeDeviceID(kernelName)]; ok {
			idx.byMajorMinor[majorMinor] = ioKey
		}
	}

	return idx
}

func getDiskstatsMap() map[string]string {
	if runtime.GOOS != "linux" {
		return nil
	}

	file, err := os.Open("/proc/diskstats")
	if err != nil {
		return nil
	}
	defer file.Close()

	out := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		out[fields[0]+":"+fields[1]] = fields[2]
	}
	return out
}

func chooseRootPath(osName string, mounts []mountRec) string {
	if osName == "linux" {
		for _, candidate := range []string{"/sysroot", "/"} {
			for _, mount := range mounts {
				if samePath(osName, mount.Path, candidate) {
					return candidate
				}
			}
		}
		for _, candidate := range []string{"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"} {
			for _, mount := range mounts {
				if samePath(osName, mount.Path, candidate) &&
					(strings.HasPrefix(mount.Source, "/dev/") || strings.HasPrefix(mount.SourceReal, "/dev/")) {
					return candidate
				}
			}
		}
		return "/"
	}

	for _, mount := range mounts {
		if samePath(osName, mount.Path, "/") || samePath(osName, mount.Path, `C:\`) {
			return mount.Path
		}
	}
	if len(mounts) > 0 {
		return mounts[0].Path
	}
	if osName == "windows" {
		return `C:\`
	}
	return "/"
}

func pruneRootMirrors(targets []*trackedDisk) []*trackedDisk {
	var root *trackedDisk
	for _, target := range targets {
		if target != nil && target.Stats != nil && target.Stats.Root {
			root = target
			break
		}
	}
	if root == nil || root.IOKey == "" {
		return targets
	}

	out := make([]*trackedDisk, 0, len(targets))
	for _, target := range targets {
		if target == nil {
			continue
		}
		if !target.Stats.Root &&
			strings.HasPrefix(target.UsagePath, "/extra-filesystems/") &&
			target.IOKey == root.IOKey {
			continue
		}
		out = append(out, target)
	}
	return out
}

func parseDiskSpecs(env string) []diskSpec {
	env = strings.TrimSpace(env)
	if env == "" {
		return nil
	}

	specs := make([]diskSpec, 0)
	for _, raw := range strings.Split(env, ",") {
		parts := strings.SplitN(strings.TrimSpace(raw), "|", 3)
		identifier := strings.TrimSpace(parts[0])
		if identifier == "" {
			continue
		}
		spec := diskSpec{Identifier: identifier}
		if len(parts) > 1 {
			spec.Alias = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			spec.IoOverride = strings.TrimSpace(parts[2])
		}
		specs = append(specs, spec)
	}
	return specs
}

func hasRootSpec(osName string, specs []diskSpec, rootPath string) bool {
	for _, spec := range specs {
		if samePath(osName, spec.Identifier, rootPath) || strings.EqualFold(spec.Alias, "root") {
			return true
		}
	}
	return false
}

func normalizePath(osName, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if osName == "windows" {
		raw = strings.ReplaceAll(raw, "/", `\`)
		if len(raw) >= 2 && raw[1] == ':' {
			drive := strings.ToLower(raw[:2])
			rest := strings.Trim(raw[2:], `\`)
			if rest == "" {
				return drive + `\`
			}
			parts := splitWindowsPath(rest)
			if len(parts) == 0 {
				return drive + `\`
			}
			return drive + `\` + strings.Join(parts, `\`)
		}
		return strings.ToLower(strings.TrimRight(raw, `\`))
	}
	return filepath.Clean(raw)
}

func splitWindowsPath(path string) []string {
	fields := strings.FieldsFunc(path, func(r rune) bool { return r == '\\' || r == '/' })
	out := make([]string, 0, len(fields))
	for _, field := range fields {
		if field != "" {
			out = append(out, field)
		}
	}
	return out
}

func samePath(osName, a, b string) bool {
	return normalizePath(osName, a) == normalizePath(osName, b)
}

func hasMountPrefix(osName, path, mount string) bool {
	p := normalizePath(osName, path)
	m := normalizePath(osName, mount)
	if p == m {
		return true
	}
	if osName == "windows" {
		if strings.HasSuffix(m, `\`) {
			return strings.HasPrefix(p, m)
		}
		return strings.HasPrefix(p, m+`\`)
	}
	if m == "/" {
		return strings.HasPrefix(p, "/")
	}
	return strings.HasPrefix(p, m+string(filepath.Separator))
}

func isAbsPath(osName, path string) bool {
	if osName == "windows" {
		path = strings.TrimSpace(path)
		return len(path) >= 3 &&
			((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
			path[1] == ':' &&
			(path[2] == '\\' || path[2] == '/')
	}
	return filepath.IsAbs(path)
}

func isDevicePath(osName, path string) bool {
	if osName == "windows" {
		return false
	}
	return strings.HasPrefix(filepath.Clean(path), "/dev/")
}

func normalizeDeviceID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, `\`, "/")
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return ""
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "/dev/") {
		return strings.TrimPrefix(lower, "/dev/")
	}
	if len(lower) == 2 && lower[1] == ':' {
		return lower
	}
	if len(lower) == 3 && lower[1] == ':' && lower[2] == '/' {
		return lower[:2]
	}
	if strings.Contains(lower, "/") {
		return strings.ToLower(pathpkg.Base(lower))
	}
	return lower
}

func parentDeviceName(raw string) string {
	device := normalizeDeviceID(raw)
	if device == "" {
		return ""
	}
	for _, prefix := range []string{"dm-", "md", "loop", "ram", "zram"} {
		if strings.HasPrefix(device, prefix) {
			return ""
		}
	}
	for _, prefix := range []string{"nvme", "mmcblk", "nda", "nvd", "ada"} {
		if strings.HasPrefix(device, prefix) {
			if idx := strings.LastIndex(device, "p"); idx > 0 && allDigits(device[idx+1:]) {
				return device[:idx]
			}
		}
	}
	if strings.HasPrefix(device, "disk") {
		if idx := strings.LastIndex(device, "s"); idx > 0 && allDigits(device[idx+1:]) {
			return device[:idx]
		}
	}

	idx := len(device)
	for idx > 0 && device[idx-1] >= '0' && device[idx-1] <= '9' {
		idx--
	}
	if idx == len(device) || idx == 0 {
		return ""
	}
	parent := strings.TrimSuffix(device[:idx], "p")
	if parent == "" || parent == device {
		return ""
	}
	return parent
}

func allDigits(v string) bool {
	if v == "" {
		return false
	}
	for _, ch := range v {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
