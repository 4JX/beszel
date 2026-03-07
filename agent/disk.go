package agent

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
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

// parseDiskEntries parses a DISKS env var into a slice of DiskEntry
// Format: <identifier>[:<alias>][:<io_device>],...
func parseDiskEntries(disksEnv string) []DiskEntry {
	var entries []DiskEntry
	if disksEnv == "" {
		return entries
	}

	for _, fsEntry := range strings.Split(disksEnv, ",") {
		fsEntry = strings.TrimSpace(fsEntry)
		if fsEntry == "" {
			continue
		}

		parts := strings.Split(fsEntry, "|")
		entry := DiskEntry{
			Identifier: strings.TrimSpace(parts[0]),
		}

		if len(parts) > 1 {
			entry.Alias = strings.TrimSpace(parts[1])
		}
		if len(parts) > 2 {
			entry.IoDevice = strings.TrimSpace(parts[2])
		}

		entries = append(entries, entry)
	}
	return entries
}

func isDockerSpecialMountpoint(mountpoint string) bool {
	switch mountpoint {
	case "/etc/hosts", "/etc/resolv.conf", "/etc/hostname":
		return true
	default:
		return false
	}
}

// Sets up the filesystems to monitor for disk usage and I/O.
func (a *Agent) initializeDiskInfo() {
	disksEnv, _ := GetEnv("DISKS")
	diskEntries := parseDiskEntries(disksEnv)

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

	// 1. Auto-add root
	rootMountPoint := a.getRootMountPoint()
	var rootEntry DiskEntry
	rootConfigured := false

	// Check if user already configured root in DISKS
	for _, entry := range diskEntries {
		if entry.Identifier == rootMountPoint || entry.Identifier == "/" || entry.Alias == "root" {
			rootConfigured = true
			break
		}
	}

	if !rootConfigured && !isWindows {
		// Detect /etc/hosts for docker overlayfs fallback
		dockerRootFound := false
		for _, p := range partitions {
			if isDockerSpecialMountpoint(p.Mountpoint) && strings.HasPrefix(p.Device, "/dev") {
				rootEntry = DiskEntry{Identifier: p.Mountpoint, Alias: "root"}
				dockerRootFound = true
				break
			}
		}
		if !dockerRootFound {
			rootEntry = DiskEntry{Identifier: rootMountPoint, Alias: "root"}
		}
		// Prepend auto-detected root
		diskEntries = append([]DiskEntry{rootEntry}, diskEntries...)
	} else if !rootConfigured && len(partitions) > 0 {
		// Windows fallback (first partition)
		rootEntry = DiskEntry{Identifier: partitions[0].Mountpoint, Alias: "root"}
		diskEntries = append([]DiskEntry{rootEntry}, diskEntries...)
	}

	// 2. Process all disk entries
	for i, entry := range diskEntries {
		isRoot := (i == 0 && !rootConfigured) || (entry.Identifier == rootMountPoint || entry.Identifier == "/" || entry.Alias == "root")

		part, err := findPartition(entry.Identifier, partitions)
		if err != nil {
			if isRoot {
				// Don't log a warning if it's the auto root and it just didn't exist
				slog.Warn("Root device not detected; root I/O disabled", "mountpoint", entry.Identifier)
				a.fsStats["root"] = &system.FsStats{Root: true, Mountpoint: entry.Identifier}
			} else {
				slog.Warn("Disk partition not found", "identifier", entry.Identifier)
			}
			continue
		}

		mountpoint := part.Mountpoint

		// Map key is mountpoint (except Windows, where we keep using device)
		key := mountpoint
		if isWindows {
			key = part.Device
		}

		if _, exists := a.fsStats[key]; exists {
			continue // Already processed
		}

		// Resolve I/O device
		var ioDevice string
		var ioAvailable bool

		if entry.IoDevice != "" {
			ioDevice = entry.IoDevice
			_, ioAvailable = diskIoCounters[ioDevice]
		} else {
			if runtime.GOOS == "linux" {
				ioDevice, ioAvailable = resolveIoDeviceForLinuxMountpoint(mountpoint, diskIoCounters)
			} else {
				ioDevice, ioAvailable = resolveKernelDeviceName(part.Device, diskIoCounters)
			}
		}

		if ioAvailable {
			a.ioDeviceForMount[key] = ioDevice
			slog.Info("Disk configured", "id", entry.Identifier, "alias", entry.Alias, "mountpoint", mountpoint, "device", part.Device, "ioDevice", ioDevice, "ioAvailable", ioAvailable)
		} else {
			slog.Warn("Disk configured", "id", entry.Identifier, "alias", entry.Alias, "mountpoint", mountpoint, "device", part.Device, "ioDevice", ioDevice, "ioAvailable", ioAvailable, "hint", "set io_device in DISKS entry")
			// Log specific missing diskstats warning
			if !isWindows && ioDevice == "" {
				slog.Warn("No I/O stats for disk", "id", entry.Identifier, "resolvedDevice", part.Device, "hint", "The device is not in /proc/diskstats. Set the io_device field to the underlying physical device, e.g.: /mnt/backup:Backup:sda1")
			}
		}

		// Add to fsStats map
		fsStats := &system.FsStats{
			Root:       isRoot,
			Mountpoint: mountpoint,
			Name:       deriveDisplayName(entry, isRoot, mountpoint),
		}
		a.fsStats[key] = fsStats
	}

	a.initializeDiskIoStats(diskIoCounters)
}

// deriveDisplayName determines the most appropriate display name for a disk entry.
func deriveDisplayName(entry DiskEntry, isRoot bool, mountpoint string) string {
	if entry.Alias != "" {
		return entry.Alias
	}
	if isRoot {
		return "root"
	}
	return filepath.Base(mountpoint)
}

// findPartition resolves an identifier to a PartitionStat.
// It handles symlinks (UUID, labels) and matching by mountpoint or device.
func findPartition(identifier string, partitions []disk.PartitionStat) (*disk.PartitionStat, error) {
	resolvedID := identifier
	if symlinkTarget, err := filepath.EvalSymlinks(identifier); err == nil {
		resolvedID = symlinkTarget
	}

	// Linux: Always try to get the raw block device first.
	// This bypasses gopsutil's bind mount handling.
	// See https://github.com/shirou/gopsutil/pull/1931/changes/e370cf64ade6646d44f98afa266b0ff19819f44d
	if runtime.GOOS == "linux" {
		// Just parse Mountpoint to find the true source via mountinfo
		if info, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(identifier)); err == nil && len(info) > 0 {
			if strings.HasPrefix(info[0].Source, "/") {
				return &disk.PartitionStat{
					Mountpoint: identifier,
					Device:     info[0].Source,
				}, nil
			}
		}
	}

	for _, p := range partitions {
		if p.Mountpoint == identifier || p.Device == resolvedID {
			return &p, nil
		}
	}

	// Bind mount fallback (directories not in partitions but have usage)
	if _, err := disk.Usage(identifier); err == nil {
		return &disk.PartitionStat{
			Mountpoint: identifier,
			Device:     identifier,
		}, nil
	}

	return nil, os.ErrNotExist
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

// resolveIoDeviceForLinuxMountpoint determines the best diskstats key for a Linux mountpoint.
func resolveIoDeviceForLinuxMountpoint(mountpoint string, diskIoCounters map[string]disk.IOCountersStat) (string, bool) {
	if runtime.GOOS != "linux" {
		return "", false
	}

	// 1. Get major:minor from mountinfo
	info, err := mountinfo.GetMounts(mountinfo.SingleEntryFilter(mountpoint))
	if err != nil || len(info) == 0 {
		return "", false
	}

	major, minor := info[0].Major, info[0].Minor

	// 2. Map major:minor to device node
	sysfsPath := fmt.Sprintf("/sys/dev/block/%d:%d", major, minor)
	target, err := filepath.EvalSymlinks(sysfsPath)
	if err != nil {
		return "", false
	}

	kernelName := filepath.Base(target)

	// 3. Try exact match
	if _, exists := diskIoCounters[kernelName]; exists {
		return kernelName, true
	}

	// 4. Try parent disk (e.g. sda1 -> sda)
	if parent := parentDiskName(kernelName); parent != "" {
		if _, exists := diskIoCounters[parent]; exists {
			return parent, true
		}
	}

	return "", false
}

// resolveKernelDeviceName determines the best diskstats key for a given device path.
// This is used for non-Linux platforms where device paths are the main key.
func resolveKernelDeviceName(devicePath string, diskIoCounters map[string]disk.IOCountersStat) (string, bool) {
	base := filepath.Base(devicePath)
	_, exists := diskIoCounters[base]
	return base, exists
}

// Sets start values for disk I/O stats.
func (a *Agent) initializeDiskIoStats(diskIoCounters map[string]disk.IOCountersStat) {
	// Rebuild fsNames deterministically to prevent memory leak on re-init
	uniqueNames := make(map[string]struct{})

	for key, stats := range a.fsStats {
		ioDevice, mapped := a.ioDeviceForMount[key]
		if !mapped {
			// No I/O device resolved for this disk
			continue
		}

		d, exists := diskIoCounters[ioDevice]
		if !exists {
			slog.Warn("Device not found in diskstats", "name", ioDevice, "key", key)
			continue
		}

		// populate initial values
		stats.Time = time.Now()
		stats.TotalRead = d.ReadBytes
		stats.TotalWrite = d.WriteBytes

		uniqueNames[ioDevice] = struct{}{}
	}

	a.fsNames = make([]string, 0, len(uniqueNames))
	for name := range uniqueNames {
		a.fsNames = append(a.fsNames, name)
	}
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
	for _, stats := range a.fsStats {
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
	// disk i/o (cache-aware per interval)
	if ioCounters, err := disk.IOCounters(a.fsNames...); err == nil {
		// Ensure map for this interval exists
		if _, ok := a.diskPrev[cacheTimeMs]; !ok {
			a.diskPrev[cacheTimeMs] = make(map[string]prevDisk)
		}
		now := time.Now()

		for key, stats := range a.fsStats {
			ioDevice, mapped := a.ioDeviceForMount[key]
			if !mapped {
				continue
			}

			d, exists := ioCounters[ioDevice]
			if !exists {
				continue
			}

			if stats == nil {
				// skip devices not tracked
				continue
			}

			// Previous snapshot for this interval and device (keyed by mountpoint)
			prev, hasPrev := a.diskPrev[cacheTimeMs][key]
			snap := prevDisk{readBytes: d.ReadBytes, writeBytes: d.WriteBytes, at: now}
			if !hasPrev {
				// Seed from agent-level fsStats if present, else seed from current
				prev = prevDisk{readBytes: stats.TotalRead, writeBytes: stats.TotalWrite, at: stats.Time}
				if prev.at.IsZero() {
					prev = snap
				}
			}

			msElapsed := uint64(now.Sub(prev.at).Milliseconds())
			if msElapsed < 100 {
				// Avoid division by zero or clock issues; update snapshot and continue
				a.diskPrev[cacheTimeMs][key] = snap
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
				a.diskPrev[cacheTimeMs][key] = snap
				// also refresh agent baseline to avoid future negatives
				a.initializeDiskIoStats(ioCounters)
				continue
			}

			// Update per-interval snapshot
			a.diskPrev[cacheTimeMs][key] = snap

			// Update global fsStats baseline for cross-interval correctness
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
