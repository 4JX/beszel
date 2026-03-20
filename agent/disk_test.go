//go:build testing

package agent

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/henrygd/beszel/internal/entities/system"
	"github.com/shirou/gopsutil/v4/disk"
)

func TestIssue1737RootDoesNotBindToBusiestExtraDisk(t *testing.T) {
	targets := materializeTrackedDisks(
		"linux",
		[]mountRec{
			{Path: "/etc/resolv.conf", Source: "/dev/sda1", SourceReal: "/dev/sda1", MajorMinor: "8:1", Root: true},
			{Path: "/extra-filesystems/sdb1__Storage", Source: "/dev/sdb1", SourceReal: "/dev/sdb1", MajorMinor: "8:17"},
			{Path: "/extra-filesystems/sdc1__Dispensable", Source: "/dev/sdc1", SourceReal: "/dev/sdc1", MajorMinor: "8:33"},
		},
		"/etc/resolv.conf",
		nil,
		buildIOIndex(map[string]disk.IOCountersStat{
			"sda1": {Name: "sda1"},
			"sdb1": {Name: "sdb1"},
			"sdc1": {Name: "sdc1"},
		}, map[string]string{
			"8:1":  "sda1",
			"8:17": "sdb1",
			"8:33": "sdc1",
		}),
	)

	root := findRootTarget(targets)
	if root == nil {
		t.Fatal("expected root target")
	}
	if root.UsagePath != "/etc/resolv.conf" || root.IOKey != "sda1" {
		t.Fatalf("expected root to resolve to /etc/resolv.conf on sda1, got %#v", root)
	}
}

func TestIssue1772FreeBSDAllowsExplicitOverride(t *testing.T) {
	targets := materializeTrackedDisks(
		"freebsd",
		[]mountRec{
			{Path: "/", Source: "zroot/ROOT/default", SourceReal: "zroot/ROOT/default", Root: true},
			{Path: "/boot/efi", Source: "/dev/gpt/efiboot0", SourceReal: "/dev/gpt/efiboot0"},
		},
		"/",
		[]diskSpec{{Identifier: "/", Alias: "root", IoOverride: "/dev/nda0"}},
		buildIOIndex(map[string]disk.IOCountersStat{
			"nda0": {Name: "nda0"},
			"nda1": {Name: "nda1"},
		}, nil),
	)

	root := findRootTarget(targets)
	if root == nil {
		t.Fatal("expected root target")
	}
	if root.IOKey != "nda0" || root.Resolution != "explicit_override" {
		t.Fatalf("expected explicit FreeBSD override to bind nda0, got %#v", root)
	}
}

func TestIssue1428PrunesRootMirrorExtras(t *testing.T) {
	targets := materializeTrackedDisks(
		"linux",
		[]mountRec{
			{Path: "/", Source: "/dev/mapper/cachedev_0", SourceReal: "/dev/dm-6", Root: true},
			{Path: "/extra-filesystems/SHR1", Source: "/dev/mapper/cachedev_1", SourceReal: "/dev/dm-7"},
			{Path: "/extra-filesystems/NVMe", Source: "/dev/mapper/cachedev_0", SourceReal: "/dev/dm-6"},
			{Path: "/extra-filesystems/Backup", Source: "/dev/usb1p1", SourceReal: "/dev/usb1p1"},
		},
		"/",
		[]diskSpec{
			{Identifier: "/"},
			{Identifier: "/extra-filesystems/SHR1", Alias: "SHR1"},
			{Identifier: "/extra-filesystems/NVMe", Alias: "NVMe"},
			{Identifier: "/extra-filesystems/Backup", Alias: "Backup"},
		},
		buildIOIndex(map[string]disk.IOCountersStat{
			"dm-6":   {Name: "dm-6"},
			"dm-7":   {Name: "dm-7"},
			"usb1p1": {Name: "usb1p1"},
		}, nil),
	)

	if len(targets) != 3 {
		t.Fatalf("expected mirrored extra to be pruned, got %d targets", len(targets))
	}
	if findTargetByPath(targets, "/extra-filesystems/NVMe") != nil {
		t.Fatalf("expected NVMe mirror to be pruned, got %#v", targets)
	}
}

func TestIssue1361WindowsPathsNormalizeAndUsageOnlyRemainsValid(t *testing.T) {
	targets := materializeTrackedDisks(
		"windows",
		[]mountRec{
			{Path: `C:\`, Source: `C:\`, SourceReal: `C:\`, Root: true},
			{Path: `D:\\`, Source: `D:\\`, SourceReal: `D:\\`},
			{Path: `W:\\`, Source: `W:\\`, SourceReal: `W:\\`},
		},
		`C:\`,
		[]diskSpec{
			{Identifier: `D:\`, Alias: "Data"},
			{Identifier: `W:\`, Alias: "Archive"},
		},
		buildIOIndex(map[string]disk.IOCountersStat{
			`C:`: {Name: `C:`},
			`D:`: {Name: `D:`},
		}, nil),
	)

	if len(targets) != 3 {
		t.Fatalf("expected root plus two configured drives, got %d", len(targets))
	}
	d := findTargetByPath(targets, `D:\\`)
	if d == nil || d.IOKey != `D:` {
		t.Fatalf("expected D drive to bind, got %#v", d)
	}
	w := findTargetByPath(targets, `W:\\`)
	if w == nil || w.IOKey != "" || w.Resolution != "usage_only" {
		t.Fatalf("expected W drive to remain usage_only, got %#v", w)
	}
}

func TestIssue1405UsesSysrootAsRoot(t *testing.T) {
	targets := materializeTrackedDisks(
		"linux",
		[]mountRec{
			{Path: "/sysroot", Source: "/dev/vda3", SourceReal: "/dev/vda3", MajorMinor: "252:3", Root: true},
			{Path: "/", Source: "overlay", SourceReal: "overlay"},
			{Path: "/boot", Source: "/dev/vda2", SourceReal: "/dev/vda2", MajorMinor: "252:2"},
		},
		"/sysroot",
		nil,
		buildIOIndex(map[string]disk.IOCountersStat{
			"vda3": {Name: "vda3"},
			"vda2": {Name: "vda2"},
		}, map[string]string{
			"252:3": "vda3",
			"252:2": "vda2",
		}),
	)

	root := findRootTarget(targets)
	if root == nil {
		t.Fatal("expected root target")
	}
	if root.UsagePath != "/sysroot" || root.IOKey != "vda3" {
		t.Fatalf("expected /sysroot to bind vda3, got %#v", root)
	}
}

func TestDarwinBindsAPFSVolumeViaParentDisk(t *testing.T) {
	targets := materializeTrackedDisks(
		"darwin",
		[]mountRec{
			{Path: "/", Source: "/dev/disk3s1", SourceReal: "/dev/disk3s1", Root: true},
		},
		"/",
		nil,
		buildIOIndex(map[string]disk.IOCountersStat{
			"disk3": {Name: "disk3"},
		}, nil),
	)

	root := findRootTarget(targets)
	if root == nil {
		t.Fatal("expected root target")
	}
	if root.IOKey != "disk3" || root.Resolution != "darwin_parent" {
		t.Fatalf("expected APFS root to bind via parent disk, got %#v", root)
	}
}

func TestUpdateDiskUsageCachesNonRootTargets(t *testing.T) {
	originalUsage := diskUsageFn
	diskUsageFn = func(path string) (*disk.UsageStat, error) {
		switch path {
		case "/":
			return &disk.UsageStat{Total: 200 * 1024 * 1024 * 1024, Used: 100 * 1024 * 1024 * 1024, UsedPercent: 50}, nil
		case "/mnt/data":
			return &disk.UsageStat{Total: 500 * 1024 * 1024 * 1024, Used: 250 * 1024 * 1024 * 1024, UsedPercent: 50}, nil
		default:
			return nil, errors.New("unexpected path")
		}
	}
	t.Cleanup(func() { diskUsageFn = originalUsage })

	agent := &Agent{
		disks: []*trackedDisk{
			{
				Key:       "/",
				UsagePath: "/",
				Stats:     &system.FsStats{Name: "root", Mountpoint: "/", Root: true},
			},
			{
				Key:       "/mnt/data",
				UsagePath: "/mnt/data",
				Stats:     &system.FsStats{Name: "data", Mountpoint: "/mnt/data", DiskTotal: 123, DiskUsed: 45},
			},
		},
		diskUsageCacheDuration: time.Hour,
		lastDiskUsageUpdate:    time.Now(),
	}

	var systemStats system.Stats
	agent.updateDiskUsage(&systemStats)

	if systemStats.DiskTotal == 0 || systemStats.DiskUsed == 0 || systemStats.DiskPct != 50 {
		t.Fatalf("expected root usage to refresh system stats, got %#v", systemStats)
	}
	extra := findTargetByPath(agent.disks, "/mnt/data")
	if extra == nil {
		t.Fatal("expected extra target")
	}
	if extra.Stats.DiskTotal != 123 || extra.Stats.DiskUsed != 45 {
		t.Fatalf("expected cached extra usage to be preserved, got %#v", extra.Stats)
	}
}

func TestUpdateDiskIoPropagatesToRootAndSharedTargets(t *testing.T) {
	originalCounters := diskIOCountersFn
	diskIOCountersFn = func(names ...string) (map[string]disk.IOCountersStat, error) {
		return map[string]disk.IOCountersStat{
			"sda1": {Name: "sda1", ReadBytes: 4_000_000, WriteBytes: 7_000_000},
		}, nil
	}
	t.Cleanup(func() { diskIOCountersFn = originalCounters })

	root := &trackedDisk{
		Key:       "/",
		UsagePath: "/",
		IOKey:     "sda1",
		Stats:     &system.FsStats{Name: "root", Mountpoint: "/", Root: true},
	}
	extra := &trackedDisk{
		Key:       "/mnt/data",
		UsagePath: "/mnt/data",
		IOKey:     "sda1",
		Stats:     &system.FsStats{Name: "data", Mountpoint: "/mnt/data"},
	}
	agent := &Agent{
		disks:      []*trackedDisk{root, extra},
		byIODevice: map[string][]*trackedDisk{"sda1": {root, extra}},
		ioDevices:  []string{"sda1"},
		prevIO: map[uint16]map[string]ioSample{
			60_000: {
				"sda1": {read: 2_000_000, write: 3_000_000, at: time.Now().Add(-1 * time.Second)},
			},
		},
	}

	var systemStats system.Stats
	agent.updateDiskIo(60_000, &systemStats)

	if root.Stats.DiskReadBytes == 0 || root.Stats.DiskWriteBytes == 0 {
		t.Fatalf("expected root throughput to be updated, got %#v", root.Stats)
	}
	if extra.Stats.DiskReadBytes != root.Stats.DiskReadBytes || extra.Stats.DiskWriteBytes != root.Stats.DiskWriteBytes {
		t.Fatalf("expected shared target throughput to match root, got root=%#v extra=%#v", root.Stats, extra.Stats)
	}
	if systemStats.DiskIO[0] != root.Stats.DiskReadBytes || systemStats.DiskIO[1] != root.Stats.DiskWriteBytes {
		t.Fatalf("expected system disk I/O to mirror root, got %#v", systemStats)
	}
}

func TestPopulateExtraFsUsesMaterializedTargetNames(t *testing.T) {
	agent := &Agent{
		disks: []*trackedDisk{
			{
				Key:       "/",
				UsagePath: "/",
				Stats:     &system.FsStats{Name: "root", Mountpoint: "/", Root: true, DiskTotal: 100, DiskUsed: 50},
			},
			{
				Key:       "/mnt/data",
				UsagePath: "/mnt/data",
				Stats:     &system.FsStats{Name: "Data", Mountpoint: "/mnt/data", DiskTotal: 200, DiskUsed: 100},
			},
			{
				Key:       "/mnt/backup",
				UsagePath: "/mnt/backup",
				Stats:     &system.FsStats{Mountpoint: "/mnt/backup", DiskTotal: 400, DiskUsed: 40},
			},
		},
	}

	var data system.CombinedData
	agent.populateExtraFs(&data)

	if _, ok := data.Stats.ExtraFs["Data"]; !ok {
		t.Fatalf("expected named extra filesystem, got %#v", data.Stats.ExtraFs)
	}
	if _, ok := data.Stats.ExtraFs["backup"]; !ok {
		t.Fatalf("expected basename fallback, got %#v", data.Stats.ExtraFs)
	}
	if data.Info.ExtraFsPct["Data"] != 50 || data.Info.ExtraFsPct["backup"] != 10 {
		t.Fatalf("expected extra filesystem percentages, got %#v", data.Info.ExtraFsPct)
	}
}

func TestLocalLinuxResolverSmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}

	counters, err := disk.IOCounters()
	if err != nil {
		t.Fatalf("collect disk counters: %v", err)
	}
	mounts := discoverMounts()
	rootPath := chooseRootPath("linux", mounts)
	targets := materializeTrackedDisks("linux", mounts, rootPath, nil, buildIOIndex(counters, getDiskstatsMap()))

	if len(targets) == 0 {
		t.Fatal("expected at least one tracked disk")
	}
	root := findRootTarget(targets)
	if root == nil || root.UsagePath == "" {
		t.Fatalf("expected resolved root target, got %#v", root)
	}
}

func findRootTarget(targets []*trackedDisk) *trackedDisk {
	for _, target := range targets {
		if target != nil && target.Stats != nil && target.Stats.Root {
			return target
		}
	}
	return nil
}

func findTargetByPath(targets []*trackedDisk, usagePath string) *trackedDisk {
	for _, target := range targets {
		if target != nil && target.UsagePath == usagePath {
			return target
		}
	}
	return nil
}
