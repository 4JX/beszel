## 📃 Description

This PR refactors how the agent discovers and configures filesystem stats (disk usage + disk I/O), with a focus on making Linux setups more reliable while simplifying configuration. The main user-facing change is a single `DISKS` environment variable that controls which mounts are monitored and (optionally) how they’re named and how their I/O device is resolved.

The motivation is to improve behavior on “non-trivial” Linux storage stacks (LUKS/dm-crypt, device-mapper paths, bind mounts, etc.) where mountpoints, `/dev/*` devices, and `/proc/diskstats` keys frequently don’t line up cleanly.

**Note:** This PR is intended as a starting point to discuss direction and tradeoffs. I’ve been iterating on several approaches and would appreciate feedback on correctness, naming semantics, and platform-specific expectations.

### What this refactor changes in practice

- **Configuration is unified** under `DISKS` instead of `FILESYSTEM` + `EXTRA_FILESYSTEMS` + `/extra-filesystems`.
- **Discovery becomes mountpoint-centric**: entries are keyed by mountpoint (Windows keeps device-based keys), avoiding collisions and reducing “guessing” from device basenames.
- **Linux device mapping is more explicit**:
  - Attempts to map a mountpoint to its underlying device by reading `/proc/self/mountinfo` (bypassing some of the confusing cases in `gopsutil.Partitions()`).
  - Attempts to map that device to a usable diskstats key for `IOCounters()` by resolving symlinks and using kernel device naming.
  - Includes a `/sys/block/<dev>/slaves` recursive fallback to find a physical I/O device when the direct device is not present in diskstats.

### `DISKS` format

`DISKS` is a comma-separated list of entries:

`<identifier>[|<alias>][|<io_device>]`

Examples:

- `DISKS=/mnt/data|Data`
- `DISKS=/mnt/backup|Backup|sda1` (force I/O device if auto-resolution fails)
- `DISKS=/` (monitor root only)

`identifier` can be a mountpoint or device path (and symlinks are resolved when possible). The `alias` becomes the display name. `io_device` can be used to override I/O mapping when kernel diskstats names don’t match the resolved device.

---

### Detection mechanisms considered (and why this PR does what it does)

1. **`gopsutil.Partitions()`**
   - _Pros_: Cross-platform, already used.
   - _Cons_: On Linux it can treat bind mounts and related cases in ways that make “mountpoint → backing device” mapping unreliable without extra logic.

2. **`syscall.Stat`**
   - _Pros_: Accurate device identity for a path.
   - _Cons_: Still requires translation to a diskstats key and doesn’t directly give “mountpoint → mount source” relationships.

3. **Manual `/proc/self/mountinfo` parsing**
   - _Pros_: Raw mount mapping used by the OS (and effectively the underlying source of truth for mounts).
   - _Cons_: Linux-only and parsing has edge cases; this PR does a minimal/targeted parse for mountpoint resolution.

_(A newer syscall alternative exists in kernel 6.8+, but is too new to rely on yet.)_

---

**Other notes / open questions**

- Root is still treated slightly specially (auto-added when not explicitly configured), but the goal is to reduce “root vs others” divergence over time.
- Docker root remains tricky. This PR improves manual control (alias `root` and/or `io_device` override), but fully automatic “correct root I/O” inside containers may not always be possible depending on visibility of host devices.
- The UI might benefit from optionally displaying mountpoint and resolved device information in addition to alias.

## 📖 Documentation

Not added yet — I’d like to validate the approach and edge cases first. If this direction is acceptable, I can follow up with a `DISKS` section and examples (including common Linux stacks and Docker cases).

## 🪵 Changelog

### ➕ Added

- `DISKS` environment variable for configuring monitored disks via a single list (identifier + optional alias + optional I/O override).
- Linux mountpoint-to-device resolution using `github.com/moby/sys/mountinfo` and major:minor device nodes to better handle bind-mount and complex storage layouts.
- Automatic I/O device resolution that tries to match kernel diskstats naming, eliminating the recursive `/sys/block/<dev>/slaves` fallback as it's non-deterministic for multi-slave stacks.

### ✏️ Changed

- Refactored disk configuration to be **mountpoint-centric** (reduces key collisions and makes monitored resources clearer).
- Root filesystem is auto-added when not explicitly configured in `DISKS` (Linux: prefers `/` or `/sysroot` based on OS detection; Windows: falls back to the first partition).

### 🔧 Fixed

- Improves I/O mapping reliability when `gopsutil.Partitions()` device names don’t directly correspond to `/proc/diskstats` keys (common with symlinks, mapper paths, and some encrypted setups).
- Targets issue: [https://github.com/henrygd/beszel/issues/1763](https://github.com/henrygd/beszel/issues/1763) (broader refactor grew out of trying to make this class of problems less fragile).

### 🗑️ Removed

- Removed `FILESYSTEM` and `EXTRA_FILESYSTEMS` environment variables.
- Removed the `/extra-filesystems` directory mount convention.

## 📷 Screenshots

N/A
