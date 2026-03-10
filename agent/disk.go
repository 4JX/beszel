package agent

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/henrygd/beszel/internal/entities/system"
	"github.com/moby/sys/mountinfo"

	"github.com/shirou/gopsutil/v4/disk"
)

type DiskEntry struct {
	Identifier string
	Alias      string
	IoDevice   string
}

type trackedDisk struct {
	key            string
	ioDevice       string
	stats          *system.FsStats
	prevByInterval map[uint16]prevDisk
}

// parseDiskEntries parses a DISKS env var into a slice of DiskEntry
// Format: <identifier>[|<alias>][|<io_device>],...
func parseDiskEntries(disksEnv, rootMountPoint string) ([]DiskEntry, bool) {
	if disksEnv == "" {
		return nil, false
	}
	entries := make([]DiskEntry, 0, strings.Count(disksEnv, ",")+1)
	seen := make(map[string]int, cap(entries))
	rootConfigured := false

	for i, fsEntry := range strings.Split(disksEnv, ",") {
		fsEntry = strings.TrimSpace(fsEntry)
		if fsEntry == "" {
			continue
		}

		parts := strings.Split(fsEntry, "|")
		entry := DiskEntry{Identifier: strings.TrimSpace(parts[0])}
		if entry.Identifier == "" {
			slog.Warn("Ignoring DISKS entry with empty identifier", "index", i)
			continue
		}
		if firstIdx, exists := seen[entry.Identifier]; exists {
			slog.Warn("Duplicate DISKS identifier; keeping first occurrence", "identifier", entry.Identifier, "firstIndex", firstIdx, "duplicateIndex", i)
			continue
		}
		seen[entry.Identifier] = i

		if len(parts) > 1 {
			entry.Alias = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			entry.IoDevice = strings.TrimSpace(parts[2])
		}
		if !rootConfigured && isRootEntry(entry, rootMountPoint) {
			rootConfigured = true
		}
		entries = append(entries, entry)
	}
	return entries, rootConfigured
}

func isRootEntry(entry DiskEntry, rootMountPoint string) bool {
	return entry.Identifier == "/" || entry.Identifier == rootMountPoint || strings.EqualFold(entry.Alias, "root")
}

func isDockerSpecialMountpoint(mountpoint string) bool {
	switch mountpoint {
	case "/etc/hosts", "/etc/resolv.conf", "/etc/hostname":
		return true
	default:
		return false
	}
}

type ioResolveSource string

const (
	ioResolveSourceOverride   ioResolveSource = "override"
	ioResolveSourceLinuxMount ioResolveSource = "linux_mountinfo"
	ioResolveSourceKernelPath ioResolveSource = "kernel_device_path"
)

type ioResolveResult struct {
	device    string
	available bool
	source    ioResolveSource
	reason    string
}

func resolveIoDeviceForEntry(entry DiskEntry, part disk.PartitionStat, diskIoCounters map[string]disk.IOCountersStat) ioResolveResult {
	if entry.IoDevice != "" {
		_, exists := diskIoCounters[entry.IoDevice]
		reason := "override_exact_match"
		if !exists {
			reason = "override_not_in_diskstats"
		}
		return ioResolveResult{
			device:    entry.IoDevice,
			available: exists,
			source:    ioResolveSourceOverride,
			reason:    reason,
		}
	}

	if runtime.GOOS == "linux" {
		ioDevice, ioAvailable, reason := resolveIoDeviceForLinuxMountpoint(part.Mountpoint, diskIoCounters)
		return ioResolveResult{
			device:    ioDevice,
			available: ioAvailable,
			source:    ioResolveSourceLinuxMount,
			reason:    reason,
		}
	}

	ioDevice, ioAvailable, reason := resolveKernelDeviceName(part.Device, diskIoCounters)
	return ioResolveResult{
		device:    ioDevice,
		available: ioAvailable,
		source:    ioResolveSourceKernelPath,
		reason:    reason,
	}
}

func prepareDiskEntries(disksEnv string, partitions []disk.PartitionStat, rootMountPoint string, isWindows bool) ([]DiskEntry, bool) {
	diskEntries, rootConfigured := parseDiskEntries(disksEnv, rootMountPoint)
	if rootConfigured {
		return diskEntries, true
	}

	rootIdentifier := rootMountPoint
	if isWindows {
		if len(partitions) == 0 {
			return diskEntries, false
		}
		rootIdentifier = partitions[0].Mountpoint
	} else {
		for _, p := range partitions {
			if isDockerSpecialMountpoint(p.Mountpoint) && strings.HasPrefix(p.Device, "/dev") {
				rootIdentifier = p.Mountpoint
				break
			}
		}
	}
	return append([]DiskEntry{{Identifier: rootIdentifier, Alias: "root"}}, diskEntries...), false
}

func ensureRootDisk(disks map[string]*trackedDisk, rootMountPoint string) {
	for _, tracked := range disks {
		if tracked != nil && tracked.stats != nil && tracked.stats.Root {
			return
		}
	}
	slog.Warn("No root entry resolved; adding usage-only root fallback", "mountpoint", rootMountPoint)
	disks[rootMountPoint] = &trackedDisk{
		key:            rootMountPoint,
		stats:          &system.FsStats{Root: true, Mountpoint: rootMountPoint, Name: "root"},
		prevByInterval: make(map[uint16]prevDisk),
	}
}

func canonicalDiskKey(identifier string, part disk.PartitionStat) string {
	if part.Mountpoint != "" {
		return part.Mountpoint
	}
	if identifier != "" {
		return identifier
	}
	return part.Device
}

// Sets up the filesystems to monitor for disk usage and I/O.
func (a *Agent) initializeDiskInfo() {
	// Rebuild tracked state on initialization to avoid stale mappings if re-run.
	a.disks = make(map[string]*trackedDisk)

	disksEnv, _ := GetEnv("DISKS")

	isWindows := runtime.GOOS == "windows"

	partitions, err := disk.Partitions(false)
	if err != nil {
		slog.Error("Error getting disk partitions", "err", err)
	}
	slog.Debug("Disk", "partitions", partitions)

	// trim trailing backslash for Windows devices (#1361)
	if isWindows {
		for i, p := range partitions {
			partitions[i].Device = strings.TrimSuffix(p.Device, "\\")
		}
	}

	diskIoCounters, err := disk.IOCounters()
	if err != nil {
		slog.Error("Error getting diskstats", "err", err)
	}
	slog.Debug("Disk I/O", "diskstats", diskIoCounters)

	// 1) Build desired tracking entries (DISKS + auto-root fallback)
	rootMountPoint := a.getRootMountPoint()
	diskEntries, rootConfigured := prepareDiskEntries(disksEnv, partitions, rootMountPoint, isWindows)

	// 2) Resolve identifiers -> mountpoints, then resolve I/O for each tracked entry
	for i, entry := range diskEntries {
		isRoot := (i == 0 && !rootConfigured) || isRootEntry(entry, rootMountPoint)

		part, found := findPartition(entry.Identifier, partitions)
		if !found {
			if isRoot {
				// Don't log a warning if it's the auto root and it just didn't exist
				slog.Warn("Root device not detected; root I/O disabled", "mountpoint", entry.Identifier)
				key := entry.Identifier
				if key == "" {
					key = rootMountPoint
				}
				a.disks[key] = &trackedDisk{
					key:            key,
					stats:          &system.FsStats{Root: true, Mountpoint: entry.Identifier, Name: "root"},
					prevByInterval: make(map[uint16]prevDisk),
				}
			} else {
				slog.Warn("Disk partition not found", "identifier", entry.Identifier)
			}
			continue
		}

		mountpoint := part.Mountpoint
		key := canonicalDiskKey(entry.Identifier, part)

		if _, exists := a.disks[key]; exists {
			continue // Already processed
		}

		// Resolve I/O device
		resolved := resolveIoDeviceForEntry(entry, part, diskIoCounters)

		if resolved.available {
			slog.Info("Disk configured", "id", entry.Identifier, "alias", entry.Alias, "mountpoint", mountpoint, "device", part.Device, "ioDevice", resolved.device, "ioAvailable", true, "ioSource", resolved.source, "ioReason", resolved.reason)
		} else {
			slog.Warn("Disk configured", "id", entry.Identifier, "alias", entry.Alias, "mountpoint", mountpoint, "device", part.Device, "ioDevice", resolved.device, "ioAvailable", false, "ioSource", resolved.source, "ioReason", resolved.reason, "hint", "set io_device in DISKS entry")
			// Log specific missing diskstats warning
			if !isWindows && resolved.device == "" {
				slog.Warn("No I/O stats for disk", "id", entry.Identifier, "resolvedDevice", part.Device, "hint", "The device is not in /proc/diskstats. Set the io_device field to the underlying physical device, e.g.: /mnt/backup:Backup:sda1")
			}
		}

		// Add to tracked disks map
		name := entry.Alias
		if name == "" {
			if isRoot {
				name = "root"
			} else {
				name = filepath.Base(mountpoint)
			}
		}
		stats := &system.FsStats{
			Root:       isRoot,
			Mountpoint: mountpoint,
			Name:       name,
		}
		tracked := &trackedDisk{
			key:            key,
			stats:          stats,
			prevByInterval: make(map[uint16]prevDisk),
		}
		if resolved.available {
			tracked.ioDevice = resolved.device
		}
		a.disks[key] = tracked
	}

	// 3) Ensure we always expose a root entry for usage collection.
	ensureRootDisk(a.disks, rootMountPoint)

	a.initializeDiskIoStats(diskIoCounters)
}

func findPartition(identifier string, partitions []disk.PartitionStat) (disk.PartitionStat, bool) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return disk.PartitionStat{}, false
	}

	// Linux mountpoint-first path: query mountinfo directly for the source device.
	if part, ok := resolveLinuxMountpointPartition(identifier); ok {
		return part, true
	}

	resolvedID := identifier
	if symlinkTarget, err := filepath.EvalSymlinks(identifier); err == nil {
		resolvedID = symlinkTarget
	}

	var deviceMatch disk.PartitionStat
	hasDeviceMatch := false
	for i := range partitions {
		if partitions[i].Mountpoint == identifier {
			return partitions[i], true
		}
		if !hasDeviceMatch && partitions[i].Device == resolvedID {
			deviceMatch = partitions[i]
			hasDeviceMatch = true
		}
	}
	if hasDeviceMatch {
		return deviceMatch, true
	}

	// Bind mount / usage-only fallback (not in partitions list).
	if _, err := disk.Usage(identifier); err == nil {
		return disk.PartitionStat{
			Mountpoint: identifier,
			Device:     identifier,
		}, true
	}

	return disk.PartitionStat{}, false
}

func linuxMountInfo(mountpoint string) (*mountinfo.Info, string) {
	if runtime.GOOS != "linux" {
		return nil, "non_linux_platform"
	}
	info, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(mountpoint))
	if err != nil {
		return nil, "mountinfo_query_failed"
	}
	if len(info) == 0 {
		return nil, "mountinfo_entry_not_found"
	}
	return info[0], ""
}

func resolveLinuxMountpointPartition(identifier string) (disk.PartitionStat, bool) {
	// Linux only: direct mountpoint resolution is the primary path for mount identifiers.
	// This bypasses gopsutil bind-mount quirks.
	if identifier != "/" {
		if !strings.HasPrefix(identifier, "/") || strings.HasPrefix(identifier, "/dev/") {
			return disk.PartitionStat{}, false
		}
	}
	info, reason := linuxMountInfo(identifier)
	if reason != "" || !strings.HasPrefix(info.Source, "/") {
		return disk.PartitionStat{}, false
	}
	return disk.PartitionStat{
		Mountpoint: identifier,
		Device:     info.Source,
	}, true
}

// parentDiskName strips trailing partition suffix: sda1→sda, nvme0n1p1→nvme0n1
func parentDiskName(name string) string {
	parent := strings.TrimRight(name, "0123456789")
	if before, ok := strings.CutSuffix(parent, "p"); ok {
		parent = before
	}
	if parent == name || parent == "" {
		return ""
	}
	return parent
}

// normalizeDeviceName canonicalizes device strings for comparisons.
func normalizeDeviceName(value string) string {
	name := filepath.Base(strings.TrimSpace(value))
	if name == "." {
		return ""
	}
	return name
}

// resolveIoDeviceFromKernelName deterministically maps a kernel/label-like
// identifier to a diskstats key using exact, parent, then normalized label/name matches.
func resolveIoDeviceFromKernelName(kernelName string, diskIoCounters map[string]disk.IOCountersStat) (string, bool, string) {
	kernelName = normalizeDeviceName(kernelName)
	if kernelName == "" {
		return "", false, "empty_kernel_name"
	}

	// 1. Exact key match in diskstats.
	if _, exists := diskIoCounters[kernelName]; exists {
		return kernelName, true, "exact_match"
	}

	// 2. Parent disk fallback for partition-like names.
	if parent := parentDiskName(kernelName); parent != "" {
		if _, exists := diskIoCounters[parent]; exists {
			return parent, true, "parent_disk_match"
		}
	}

	// 3. Deterministic normalized name/label match.
	for _, d := range diskIoCounters {
		if normalizeDeviceName(d.Name) == kernelName {
			return d.Name, true, "normalized_name_match"
		}
		if d.Label != "" && normalizeDeviceName(d.Label) == kernelName {
			return d.Name, true, "label_match"
		}
	}

	return kernelName, false, "device_not_in_diskstats"
}

// resolveIoDeviceForLinuxMountpoint determines the best diskstats key for a Linux mountpoint.
func resolveIoDeviceForLinuxMountpoint(mountpoint string, diskIoCounters map[string]disk.IOCountersStat) (string, bool, string) {
	info, reason := linuxMountInfo(mountpoint)
	if reason != "" {
		return "", false, reason
	}

	major, minor := info.Major, info.Minor

	// 2. Map major:minor to device node
	sysfsPath := fmt.Sprintf("/sys/dev/block/%d:%d", major, minor)
	target, err := filepath.EvalSymlinks(sysfsPath)
	if err != nil {
		return "", false, "sysfs_dev_block_not_found"
	}

	kernelName := filepath.Base(target)
	if kernelName == "" || kernelName == "." {
		return "", false, "sysfs_kernel_name_empty"
	}

	ioDevice, ioAvailable, reason := resolveIoDeviceFromKernelName(kernelName, diskIoCounters)
	return ioDevice, ioAvailable, "linux_" + reason
}

// resolveKernelDeviceName determines the best diskstats key for a given device path.
// This is used for non-Linux platforms where device paths are the main key.
func resolveKernelDeviceName(devicePath string, diskIoCounters map[string]disk.IOCountersStat) (string, bool, string) {
	base := normalizeDeviceName(devicePath)
	if base == "" {
		return "", false, "empty_device_path"
	}
	return resolveIoDeviceFromKernelName(base, diskIoCounters)
}

// Sets start values for disk I/O stats.
func (a *Agent) initializeDiskIoStats(diskIoCounters map[string]disk.IOCountersStat) {
	for _, tracked := range a.disks {
		if tracked == nil || tracked.stats == nil || tracked.ioDevice == "" {
			continue
		}
		d, exists := diskIoCounters[tracked.ioDevice]
		if !exists {
			slog.Warn("Device not found in diskstats", "name", tracked.ioDevice, "key", tracked.key)
			continue
		}
		tracked.stats.Time = time.Now()
		tracked.stats.TotalRead = d.ReadBytes
		tracked.stats.TotalWrite = d.WriteBytes
	}
}

func (a *Agent) trackedIoDevices() []string {
	uniqueNames := make(map[string]struct{})
	for _, tracked := range a.disks {
		if tracked == nil || tracked.ioDevice == "" {
			continue
		}
		uniqueNames[tracked.ioDevice] = struct{}{}
	}
	ioDevices := make([]string, 0, len(uniqueNames))
	for name := range uniqueNames {
		ioDevices = append(ioDevices, name)
	}
	sort.Strings(ioDevices)
	return ioDevices
}

// Updates disk usage statistics for all monitored filesystems
func (a *Agent) updateDiskUsage(systemStats *system.Stats) {
	// Check if we should skip extra filesystem collection to avoid waking sleeping disks.
	// Root filesystem is always updated since it can't be sleeping while the agent runs.
	// Always collect on first call (lastDiskUsageUpdate is zero) or if caching is disabled.
	cacheExtraFs := a.diskUsageCacheDuration > 0 &&
		!a.lastDiskUsageUpdate.IsZero() &&
		time.Since(a.lastDiskUsageUpdate) < a.diskUsageCacheDuration

	// disk usage
	for _, tracked := range a.disks {
		if tracked == nil || tracked.stats == nil {
			continue
		}
		stats := tracked.stats
		// Skip non-root filesystems if caching is active
		if cacheExtraFs && !stats.Root {
			continue
		}
		if d, err := disk.Usage(stats.Mountpoint); err == nil {
			stats.DiskTotal = bytesToGigabytes(d.Total)
			stats.DiskUsed = bytesToGigabytes(d.Used)
			if stats.Root {
				systemStats.DiskTotal = bytesToGigabytes(d.Total)
				systemStats.DiskUsed = bytesToGigabytes(d.Used)
				systemStats.DiskPct = twoDecimals(d.UsedPercent)
			}
		} else {
			// reset stats if error (likely unmounted)
			slog.Error("Error getting disk stats", "name", stats.Mountpoint, "err", err)
			stats.DiskTotal = 0
			stats.DiskUsed = 0
			stats.TotalRead = 0
			stats.TotalWrite = 0
		}
	}

	// Update the last disk usage update time when we've collected extra filesystems
	if !cacheExtraFs {
		a.lastDiskUsageUpdate = time.Now()
	}
}

// Updates disk I/O statistics for all monitored filesystems
func (a *Agent) updateDiskIo(cacheTimeMs uint16, systemStats *system.Stats) {
	ioDevices := a.trackedIoDevices()
	if len(ioDevices) == 0 {
		return
	}

	// disk i/o (cache-aware per interval)
	if ioCounters, err := disk.IOCounters(ioDevices...); err == nil {
		now := time.Now()

		for _, tracked := range a.disks {
			if tracked == nil || tracked.stats == nil || tracked.ioDevice == "" {
				continue
			}
			stats := tracked.stats

			d, exists := ioCounters[tracked.ioDevice]
			if !exists {
				continue
			}

			// Previous snapshot for this interval and device (keyed by mountpoint)
			prev, hasPrev := tracked.prevByInterval[cacheTimeMs]
			snap := prevDisk{readBytes: d.ReadBytes, writeBytes: d.WriteBytes, at: now}
			if !hasPrev {
				// Seed from tracked baseline if present, else seed from current
				prev = prevDisk{readBytes: stats.TotalRead, writeBytes: stats.TotalWrite, at: stats.Time}
				if prev.at.IsZero() {
					prev = snap
				}
			}

			msElapsed := uint64(now.Sub(prev.at).Milliseconds())
			if msElapsed < 100 {
				// Avoid division by zero or clock issues; update snapshot and continue
				tracked.prevByInterval[cacheTimeMs] = snap
				continue
			}

			diskIORead := (d.ReadBytes - prev.readBytes) * 1000 / msElapsed
			diskIOWrite := (d.WriteBytes - prev.writeBytes) * 1000 / msElapsed
			readMbPerSecond := bytesToMegabytes(float64(diskIORead))
			writeMbPerSecond := bytesToMegabytes(float64(diskIOWrite))

			// validate values
			if readMbPerSecond > 50_000 || writeMbPerSecond > 50_000 {
				slog.Warn("Invalid disk I/O. Resetting.", "name", d.Name, "read", readMbPerSecond, "write", writeMbPerSecond)
				// Reset interval snapshot and seed from current
				tracked.prevByInterval[cacheTimeMs] = snap
				// also refresh agent baseline to avoid future negatives
				a.initializeDiskIoStats(ioCounters)
				continue
			}

			// Update per-interval snapshot
			tracked.prevByInterval[cacheTimeMs] = snap

			// Update tracked baseline for cross-interval correctness
			stats.Time = now
			stats.TotalRead = d.ReadBytes
			stats.TotalWrite = d.WriteBytes
			stats.DiskReadPs = readMbPerSecond
			stats.DiskWritePs = writeMbPerSecond
			stats.DiskReadBytes = diskIORead
			stats.DiskWriteBytes = diskIOWrite

			if stats.Root {
				systemStats.DiskReadPs = stats.DiskReadPs
				systemStats.DiskWritePs = stats.DiskWritePs
				systemStats.DiskIO[0] = diskIORead
				systemStats.DiskIO[1] = diskIOWrite
			}
		}
	}
}

// getRootMountPoint returns the appropriate root mount point for the system
// For immutable systems like Fedora Silverblue, it returns /sysroot instead of /
func (a *Agent) getRootMountPoint() string {
	// 1. Check if /etc/os-release contains indicators of an immutable system
	if osReleaseContent, err := os.ReadFile("/etc/os-release"); err == nil {
		content := string(osReleaseContent)
		if strings.Contains(content, "fedora") && strings.Contains(content, "silverblue") ||
			strings.Contains(content, "coreos") ||
			strings.Contains(content, "flatcar") ||
			strings.Contains(content, "rhel-atomic") ||
			strings.Contains(content, "centos-atomic") {
			// Verify that /sysroot exists before returning it
			if _, err := os.Stat("/sysroot"); err == nil {
				return "/sysroot"
			}
		}
	}

	// 2. Check if /run/ostree is present (ostree-based systems like Silverblue)
	if _, err := os.Stat("/run/ostree"); err == nil {
		// Verify that /sysroot exists before returning it
		if _, err := os.Stat("/sysroot"); err == nil {
			return "/sysroot"
		}
	}

	return "/"
}
