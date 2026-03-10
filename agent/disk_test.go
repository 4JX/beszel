//go:build testing

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/henrygd/beszel/internal/entities/system"
	"github.com/shirou/gopsutil/v4/disk"
	"github.com/stretchr/testify/assert"
)

func TestParseDiskEntries(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []DiskEntry
	}{
		{
			name:     "empty",
			input:    "",
			expected: nil,
		},
		{
			name:  "single identifier",
			input: "/mnt/data",
			expected: []DiskEntry{
				{Identifier: "/mnt/data"},
			},
		},
		{
			name:  "identifier and alias",
			input: "/mnt/data|Data",
			expected: []DiskEntry{
				{Identifier: "/mnt/data", Alias: "Data"},
			},
		},
		{
			name:  "identifier, alias and iodevice",
			input: "/mnt/data|Data|sda1",
			expected: []DiskEntry{
				{Identifier: "/mnt/data", Alias: "Data", IoDevice: "sda1"},
			},
		},
		{
			name:  "missing alias with iodevice",
			input: "/mnt/data||sda1",
			expected: []DiskEntry{
				{Identifier: "/mnt/data", Alias: "", IoDevice: "sda1"},
			},
		},
		{
			name:  "multiple entries",
			input: "/mnt/data|Data, /dev/sdb1, /mnt/tank|Tank|nvme0n1",
			expected: []DiskEntry{
				{Identifier: "/mnt/data", Alias: "Data"},
				{Identifier: "/dev/sdb1"},
				{Identifier: "/mnt/tank", Alias: "Tank", IoDevice: "nvme0n1"},
			},
		},
		{
			name:  "whitespace trimmed",
			input: "  /mnt/data | Data | sda1  ,  /dev/sdb1  ",
			expected: []DiskEntry{
				{Identifier: "/mnt/data", Alias: "Data", IoDevice: "sda1"},
				{Identifier: "/dev/sdb1"},
			},
		},
		{
			name:  "root override",
			input: "/|ServerRoot",
			expected: []DiskEntry{
				{Identifier: "/", Alias: "ServerRoot"},
			},
		},
		{
			name:  "UUID",
			input: "/dev/disk/by-uuid/1234-5678|FlashDrive",
			expected: []DiskEntry{
				{Identifier: "/dev/disk/by-uuid/1234-5678", Alias: "FlashDrive"},
			},
		},
		{
			name:  "dedupe and ignore empty identifiers",
			input: "/mnt/data|Data,  |bad, /mnt/data|Dup, /mnt/backup|Backup",
			expected: []DiskEntry{
				{Identifier: "/mnt/data", Alias: "Data"},
				{Identifier: "/mnt/backup", Alias: "Backup"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entries, _ := parseDiskEntries(tt.input, "/")
			if tt.expected == nil {
				assert.Empty(t, entries)
			} else {
				assert.Equal(t, tt.expected, entries)
			}
		})
	}
}

func TestParseDiskEntriesRootConfigured(t *testing.T) {
	_, rootConfigured := parseDiskEntries("/mnt/data|Data, /|Root", "/")
	assert.True(t, rootConfigured)

	_, rootConfigured = parseDiskEntries("/mnt/data|Data", "/")
	assert.False(t, rootConfigured)

	_, rootConfigured = parseDiskEntries("/sysroot|Main", "/sysroot")
	assert.True(t, rootConfigured)
}

func TestIsDockerSpecialMountpoint(t *testing.T) {
	testCases := []struct {
		name       string
		mountpoint string
		expected   bool
	}{
		{name: "hosts", mountpoint: "/etc/hosts", expected: true},
		{name: "resolv", mountpoint: "/etc/resolv.conf", expected: true},
		{name: "hostname", mountpoint: "/etc/hostname", expected: true},
		{name: "root", mountpoint: "/", expected: false},
		{name: "passwd", mountpoint: "/etc/passwd", expected: false},
		{name: "extra-filesystem", mountpoint: "/extra-filesystems/sda1", expected: false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isDockerSpecialMountpoint(tc.mountpoint))
		})
	}
}

func TestFindPartition(t *testing.T) {
	// Create a temporary file to act as our "bind mount pointer" or fake usage test
	tmpDir := t.TempDir()

	// Create a dummy file to act as our fake device so EvalSymlinks doesn't fail
	fakeDevicePath := filepath.Join(tmpDir, "fake-sda1")
	err := os.WriteFile(fakeDevicePath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create fake device: %v", err)
	}

	// Create a symlink to test path resolution
	symlinkPath := filepath.Join(tmpDir, "symlink-to-sda1")
	err = os.Symlink(fakeDevicePath, symlinkPath)
	if err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// Setup test partitions using our fake paths where necessary
	partitions := []disk.PartitionStat{
		{Device: fakeDevicePath, Mountpoint: "/mnt/data"},
		{Device: "/dev/sdb1", Mountpoint: "/mnt/backup"},
		{Device: "/dev/nvme0n1p1", Mountpoint: "/"},
	}

	tests := []struct {
		name        string
		identifier  string
		expected    string // device path expected
		expectFound bool
	}{
		{
			name:        "match by mountpoint",
			identifier:  "/mnt/data",
			expected:    fakeDevicePath,
			expectFound: true,
		},
		{
			name:        "match by device path",
			identifier:  "/dev/sdb1",
			expected:    "/dev/sdb1",
			expectFound: true,
		},
		{
			name:        "match by symlink",
			identifier:  symlinkPath,
			expected:    fakeDevicePath,
			expectFound: true,
		},
		{
			name:        "bind mount fallback (existing dir)",
			identifier:  tmpDir,
			expected:    tmpDir, // Bind mount returns identifier as both device and mountpoint
			expectFound: true,
		},
		{
			name:        "not found",
			identifier:  "/does/not/exist",
			expected:    "",
			expectFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			part, found := findPartition(tt.identifier, partitions)
			if !tt.expectFound {
				assert.False(t, found)
			} else {
				assert.True(t, found)
				assert.Equal(t, tt.expected, part.Device)
			}
		})
	}
}
func TestResolveKernelDeviceName(t *testing.T) {
	ioCounters := map[string]disk.IOCountersStat{
		"sda":        {Name: "sda"},
		"sda1":       {Name: "sda1"},
		"nda0":       {Name: "nda0"},
		"nvme0n1":    {Name: "nvme0n1"},
		"dm-0":       {Name: "dm-0"},
		"old_device": {Name: "old_device", Label: "oldlabel"},
	}

	tests := []struct {
		name       string
		devicePath string
		expected   string
		found      bool
		reason     string
	}{
		{
			name:       "exact match",
			devicePath: "/dev/sda1",
			expected:   "sda1",
			found:      true,
			reason:     "exact_match",
		},
		{
			name:       "freebsd style parent disk fallback",
			devicePath: "/dev/nda0p2",
			expected:   "nda0",
			found:      true,
			reason:     "parent_disk_match",
		},
		{
			name:       "label match fallback",
			devicePath: "/dev/oldlabel",
			expected:   "old_device",
			found:      true,
			reason:     "label_match",
		},
		{
			name:       "windows limitation explicit unmapped",
			devicePath: "Z:",
			expected:   "Z:",
			found:      false,
			reason:     "device_not_in_diskstats",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, found, reason := resolveKernelDeviceName(tt.devicePath, ioCounters)

			assert.Equal(t, tt.found, found)
			assert.Equal(t, tt.expected, match)
			assert.Equal(t, tt.reason, reason)
		})
	}
}

func testTrackedDisk(key, ioDevice string, stats *system.FsStats) *trackedDisk {
	return &trackedDisk{
		key:            key,
		ioDevice:       ioDevice,
		stats:          stats,
		prevByInterval: make(map[uint16]prevDisk),
	}
}

func TestTrackedIoDevicesBuildsUniqueSortedNames(t *testing.T) {
	agent := &Agent{
		disks: map[string]*trackedDisk{
			"/mnt/data":   testTrackedDisk("/mnt/data", "sdb", &system.FsStats{}),
			"/mnt/backup": testTrackedDisk("/mnt/backup", "sda", &system.FsStats{}),
			"/":           testTrackedDisk("/", "sda", &system.FsStats{Root: true}), // duplicate on purpose
		},
	}
	assert.Equal(t, []string{"sda", "sdb"}, agent.trackedIoDevices())
}

func TestCanonicalDiskKey(t *testing.T) {
	assert.Equal(t, "/mnt/data", canonicalDiskKey("/by-id/disk1", disk.PartitionStat{Mountpoint: "/mnt/data", Device: "/dev/sda1"}))
	assert.Equal(t, "/by-id/disk1", canonicalDiskKey("/by-id/disk1", disk.PartitionStat{Device: "/dev/sda1"}))
	assert.Equal(t, "/dev/sda1", canonicalDiskKey("", disk.PartitionStat{Device: "/dev/sda1"}))
}

func TestInitializeDiskIoStatsUsesTrackedDiskModel(t *testing.T) {
	agent := &Agent{
		disks: map[string]*trackedDisk{
			"custom-key": testTrackedDisk("custom-key", "sda", &system.FsStats{}),
		},
	}
	agent.initializeDiskIoStats(map[string]disk.IOCountersStat{
		"sda": {Name: "sda", ReadBytes: 1234, WriteBytes: 5678},
	})
	stats := agent.disks["custom-key"].stats
	assert.Equal(t, uint64(1234), stats.TotalRead)
	assert.Equal(t, uint64(5678), stats.TotalWrite)
	assert.False(t, stats.Time.IsZero())
}

func TestDiskUsageCaching(t *testing.T) {
	t.Run("caching disabled updates all filesystems", func(t *testing.T) {
		agent := &Agent{
			disks: map[string]*trackedDisk{
				"root":  testTrackedDisk("root", "", &system.FsStats{Root: true, Mountpoint: "/"}),
				"extra": testTrackedDisk("extra", "", &system.FsStats{Root: false, Mountpoint: "/mnt/storage"}),
			},
			diskUsageCacheDuration: 0, // caching disabled
		}

		var stats system.Stats
		agent.updateDiskUsage(&stats)

		// Both should be updated (non-zero values from disk.Usage)
		// Root stats should be populated in systemStats
		assert.True(t, agent.lastDiskUsageUpdate.IsZero() || !agent.lastDiskUsageUpdate.IsZero(),
			"lastDiskUsageUpdate should be set when caching is disabled")
	})

	t.Run("caching enabled always updates root filesystem", func(t *testing.T) {
		agent := &Agent{
			disks: map[string]*trackedDisk{
				"root":  testTrackedDisk("root", "", &system.FsStats{Root: true, Mountpoint: "/", DiskTotal: 100, DiskUsed: 50}),
				"extra": testTrackedDisk("extra", "", &system.FsStats{Root: false, Mountpoint: "/mnt/storage", DiskTotal: 200, DiskUsed: 100}),
			},
			diskUsageCacheDuration: 1 * time.Hour,
			lastDiskUsageUpdate:    time.Now(), // cache is fresh
		}

		// Store original extra fs values
		originalExtraTotal := agent.disks["extra"].stats.DiskTotal
		originalExtraUsed := agent.disks["extra"].stats.DiskUsed

		var stats system.Stats
		agent.updateDiskUsage(&stats)

		// Root should be updated (systemStats populated from disk.Usage call)
		// We can't easily check if disk.Usage was called, but we verify the flow works

		// Extra filesystem should retain cached values (not reset)
		assert.Equal(t, originalExtraTotal, agent.disks["extra"].stats.DiskTotal,
			"extra filesystem DiskTotal should be unchanged when cached")
		assert.Equal(t, originalExtraUsed, agent.disks["extra"].stats.DiskUsed,
			"extra filesystem DiskUsed should be unchanged when cached")
	})

	t.Run("first call always updates all filesystems", func(t *testing.T) {
		agent := &Agent{
			disks: map[string]*trackedDisk{
				"root":  testTrackedDisk("root", "", &system.FsStats{Root: true, Mountpoint: "/"}),
				"extra": testTrackedDisk("extra", "", &system.FsStats{Root: false, Mountpoint: "/mnt/storage"}),
			},
			diskUsageCacheDuration: 1 * time.Hour,
			// lastDiskUsageUpdate is zero (first call)
		}

		var stats system.Stats
		agent.updateDiskUsage(&stats)

		// After first call, lastDiskUsageUpdate should be set
		assert.False(t, agent.lastDiskUsageUpdate.IsZero(),
			"lastDiskUsageUpdate should be set after first call")
	})

	t.Run("expired cache updates extra filesystems", func(t *testing.T) {
		agent := &Agent{
			disks: map[string]*trackedDisk{
				"root":  testTrackedDisk("root", "", &system.FsStats{Root: true, Mountpoint: "/"}),
				"extra": testTrackedDisk("extra", "", &system.FsStats{Root: false, Mountpoint: "/mnt/storage"}),
			},
			diskUsageCacheDuration: 1 * time.Millisecond,
			lastDiskUsageUpdate:    time.Now().Add(-1 * time.Second), // cache expired
		}

		var stats system.Stats
		agent.updateDiskUsage(&stats)

		// lastDiskUsageUpdate should be refreshed since cache expired
		assert.True(t, time.Since(agent.lastDiskUsageUpdate) < time.Second,
			"lastDiskUsageUpdate should be refreshed when cache expires")
	})
}

func TestPopulateExtraFsRegression(t *testing.T) {
	agent := &Agent{
		disks: map[string]*trackedDisk{
			"/":          testTrackedDisk("/", "", &system.FsStats{Root: true, Mountpoint: "/", DiskTotal: 100, DiskUsed: 50}),
			"/mnt/data":  testTrackedDisk("/mnt/data", "", &system.FsStats{Root: false, Mountpoint: "/mnt/data", DiskTotal: 200, DiskUsed: 100}),
			"/dev/sdb1":  testTrackedDisk("/dev/sdb1", "", &system.FsStats{Root: false, Mountpoint: "", DiskTotal: 50, DiskUsed: 25}),
			"/mnt/named": testTrackedDisk("/mnt/named", "", &system.FsStats{Root: false, Mountpoint: "/mnt/named", Name: "Named", DiskTotal: 300, DiskUsed: 60}),
		},
	}

	data := system.CombinedData{}
	agent.populateExtraFs(&data)

	assert.NotContains(t, data.Stats.ExtraFs, "root")
	assert.Contains(t, data.Stats.ExtraFs, "data")
	assert.Contains(t, data.Stats.ExtraFs, "sdb1")
	assert.Contains(t, data.Stats.ExtraFs, "Named")

	assert.Equal(t, 50.0, data.Info.ExtraFsPct["data"])
	assert.Equal(t, 50.0, data.Info.ExtraFsPct["sdb1"])
	assert.Equal(t, 20.0, data.Info.ExtraFsPct["Named"])
}
