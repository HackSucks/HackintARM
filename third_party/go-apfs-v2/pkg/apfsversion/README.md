# APFS implementation versions

`apfsversion` reads the version stamps Apple's APFS implementation leaves on
disk, attributes them to macOS releases, and keeps a small evidence ledger of
which host drivers can safely mount which images natively. It never mounts
anything; inspection goes through the portable reader in `pkg/apfs`.

```go
inspection, err := apfsversion.Inspect("image.dmg", 15) // 15, 26, 27, or 0 to skip names
if err != nil {
    return err
}
host := apfsversion.MustParse("2332.140.13.702.2") // the receiving kernel's apfs_kext build
assessment := apfsversion.AssessNativeMount(host, inspection.Image(0))
if err := assessment.Error(); err != nil {
    return err // *apfsversion.MountError with Verdict, Code and Reason
}
```

Three stamps exist. Each volume superblock records `apfs_formatted_by` and up
to eight `apfs_modified_by` writers as `newfs_apfs (2811.160.7.0.4)` or
`apfs_kext (2811.160.7.0.4)`; `ParseStamp` reads them and `go-apfs (apfswrite)`
parses as a non-Apple stamp without a version. The container superblock records
`nx_newest_mounted_version` as a packed integer, `a·10^12 + b·10^9 + c·10^6 +
d·10^3 + e`, which `DecodePacked` and `EncodePacked` convert; none of this is in
Apple's 2020 APFS reference, and the encodings were derived from images made on
macOS 15, 26 and 27. The leading component is the build series one macOS release
ships: `Releases` and `MacOSMajor` attribute 2313 to 2332 to macOS 15, 2632 and
2811 to macOS 26 and 3288 to macOS 27, naming the source of each row.

The ledger exists for one proven failure. The macOS 15 driver deadlocks the
whole kernel's disk I/O while mounting, or within seconds of sustained access
to, a volume whose directories hold names that macOS 26 or 27 stored using
Unicode 16 code points and that macOS 15 cannot normalize. The on-disk
structures of such a volume are otherwise identical to what macOS 15 writes, and
swapping the version stamps in either direction neither causes nor prevents the
failure, so the assessment is keyed on inspected filename content, using the
same per-release admission tables the writer applies at creation
(`internal/nameunicode`). `AssessNativeMount` returns `Supported`,
`KnownDeadlock` or `Unknown`; a newer writer whose names were not inspected is
`Unknown`, never silently supported.
