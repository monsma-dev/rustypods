#!/usr/bin/env python3
"""Repair owners in a rootfs imported from a distrobox before the import
remapped podman's keep-id ids (rustypodsd < 7c96a58).

Such an import recorded namespace ids instead of container ids: container
root became uid 1 (`bin`), container uid N < 1000 became N+1, and the
keep-id user became 0. This walks one rootfs (an image or a pod) and:

  * entries whose ctime predates the unpack boundary (still exactly as the
    import left them) get the inverse keep-id map on uid and gid;
  * later entries only get uid/gid 1 -> 0 with --later-uid1-is-root. On
    Arch, `bin` owns nothing, so a uid-1 directory that pacman touched
    after the import is still shifted root. Leave the flag off on distros
    where uid 1 owns real files (Debian: `daemon`).

The boundary is the ctime of the first uid-0 entry below the top dir: the
daemon's own post-import writes (rustypods-agent.service) and the first
boot's tmpfiles output are correctly owned and come right after the unpack.
Pass --boundary EPOCH to override.

Dry-run by default. --apply changes owners, then restores each non-symlink
mode, because chown clears setuid/setgid. Snapshot the pod first
(`rustypods commit <pod>`). Never follows symlinks and never leaves the
rootfs filesystem.
"""

import argparse
import datetime
import os
import stat
import sys


def parse_map(spec):
    out = []
    for part in spec.split(","):
        c, h, n = (int(x) for x in part.split(":"))
        if n <= 0:
            raise ValueError(f"empty range {part!r}")
        out.append((c, h, n))
    return out


def invert(ranges, ns_id):
    for c, h, n in ranges:
        if h <= ns_id < h + n:
            return c + (ns_id - h)
    return ns_id


def walk(root):
    root_dev = os.lstat(root).st_dev
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        keep = []
        for d in dirnames:
            p = os.path.join(dirpath, d)
            st = os.lstat(p)
            if stat.S_ISDIR(st.st_mode) and st.st_dev != root_dev:
                print(f"skip (other filesystem): {p}", file=sys.stderr)
                continue
            keep.append(d)
            yield p, st
        dirnames[:] = keep
        for f in filenames:
            p = os.path.join(dirpath, f)
            yield p, os.lstat(p)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("rootfs", help="e.g. /var/lib/rustypods/pods/dev")
    ap.add_argument(
        "--map",
        default="0:1:1000,1000:0:1,1001:1001:64536",
        help="podman IDMappings UidMap/GidMap as container:namespace:len,... "
        "(default: distrobox keep-id for uid 1000)",
    )
    ap.add_argument("--boundary", type=float, help="unpack end as epoch seconds")
    ap.add_argument("--later-uid1-is-root", action="store_true")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    root = os.path.realpath(a.rootfs)
    if root == "/" or not os.path.isdir(root):
        sys.exit(f"refusing rootfs {root!r}")
    if a.apply and os.geteuid() != 0:
        sys.exit("--apply needs root")
    ranges = parse_map(a.map)

    entries = [(root, os.lstat(root))] + list(walk(root))
    if a.boundary is not None:
        boundary_ns = int(a.boundary * 1e9)
    else:
        zero = [st.st_ctime_ns for p, st in entries[1:] if st.st_uid == 0]
        boundary_ns = min(zero) if zero else None
    when = (
        datetime.datetime.fromtimestamp(boundary_ns / 1e9).isoformat(timespec="milliseconds")
        if boundary_ns is not None
        else "none (every entry treated as imported)"
    )
    print(f"rootfs:   {root}\nboundary: {when}")

    changes = []
    for p, st in entries:
        uid, gid = st.st_uid, st.st_gid
        if boundary_ns is None or st.st_ctime_ns < boundary_ns:
            nu, ng = invert(ranges, uid), invert(ranges, gid)
            if uid == 0:
                nu = 0
            if gid == 0:
                ng = 0
        elif a.later_uid1_is_root:
            nu, ng = (0 if uid == 1 else uid), (0 if gid == 1 else gid)
        else:
            continue
        if (nu, ng) != (uid, gid):
            changes.append((p, st, nu, ng))

    summary = {}
    for _, st, nu, ng in changes:
        k = f"{st.st_uid}:{st.st_gid} -> {nu}:{ng}"
        summary[k] = summary.get(k, 0) + 1
    print(f"entries:  {len(entries)}, to change: {len(changes)}")
    for k, n in sorted(summary.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>7}  {k}")

    if not a.apply:
        for p, st, nu, ng in changes[:15]:
            print(f"  {st.st_uid}:{st.st_gid} -> {nu}:{ng}  {oct(stat.S_IMODE(st.st_mode))}  {p}")
        print("dry run — pass --apply to change owners")
        return

    for p, st, nu, ng in changes:
        os.chown(p, nu, ng, follow_symlinks=False)
        if not stat.S_ISLNK(st.st_mode):
            os.chmod(p, stat.S_IMODE(st.st_mode))
    print(f"changed {len(changes)} entries")


if __name__ == "__main__":
    main()
