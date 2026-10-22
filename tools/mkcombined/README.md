# mkcombined — build one APFS container holding System + Data + Preboot

`mkapfs` (apfsprogs) only ever produces a single-volume container, and the Linux
kernel driver can write files but cannot create volumes.  Creating a container
that looks like a real macOS installation therefore needs a writer that can
emit several volumes with roles and a shared volume group.  That is
[`go-apfs`](https://github.com/deploymenttheory/go-apfs-v2), a pure-Go APFS
toolkit (MIT).  `mkcombined` is the thin driver around its `apfswrite` package.

## What it does

1. Opens the decrypted OS root image and walks volume 0.
2. Rebuilds the whole tree as writer entries: names, modes, uid/gid, all four
   timestamps, BSD flags, extended attributes, resource forks, symbolic links
   and hard-link groups.  File contents are not read into memory — each file is
   a `DataValue` that streams from the source image; `decmpfs` files keep their
   compressed form (attribute copied, data fork left empty).
3. Writes a new container with three volumes:

   | # | name | role | volume group |
   |---|------|------|--------------|
   | 0 | Macintosh HD | System | yes |
   | 1 | Macintosh HD - Data | Data | yes |
   | 2 | Preboot | Preboot | — |

   The System volume keeps the source volume's UUID, because `/chosen/boot-uuid`
   in the generated ADT names it.

The Data and Preboot volumes are created with only a skeleton (the firmlink
targets macOS expects to find there), so the OS has somewhere to write.

## Usage

```console
$ go build -o mkcombined .
$ ./mkcombined -src /path/to/System-root.img -out /path/to/combined.img -size 19327352832
```

`-size` is the container size in bytes and must leave room for the source data
plus the Data volume.  `-subtree DIR` copies only one directory (used for
fidelity tests), `-noextra` omits the Data/Preboot volumes, `-dry` walks only.

## NTFS3

If the output lives on an NTFS3 volume, the writer's final one-byte write past
EOF fails with `EINVAL`: NTFS3 will not extend a file across a hole.  The last
step of `apfswrite` only sets the file length — every real block is already on
disk — so `mkcombined` catches that error and appends zeroes from EOF, which is
a contiguous grow and is accepted.

## Verification

```console
$ apfs info combined.img      # three volumes, roles, shared group
```

The contents, modes and times of the copied volume match the source; on the
27.0 (26A428) root this reproduces exactly 280853 files, 186065 directories and
17096 symlinks while preserving the compressed form (979 MB of logical data in
`System/Library/CoreServices` lands in 640 MB on disk).
