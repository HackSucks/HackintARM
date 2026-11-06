# OS version profiles

`osversion` separates a macOS compatibility target from the operating system
running a Go program. Use it when native APIs have different behavior between
macOS releases, or when Linux and Windows need to reproduce a particular macOS
release's behavior.

```go
version, err := osversion.Parse("15.7.1")
if err != nil {
    return err
}
profile, err := osversion.ProfileForMacOS(version)
if err != nil {
    return err
}
// Pass version/profile to the feature that owns the native behavior.
```

The package recognises macOS 15, 26 and 27. Numeric minor and patch versions are
retained and can be compared where evidence establishes a change within a major
release. Unknown major versions return `ErrMacOSProfile`; they never silently
inherit the newest or nearest profile. `ParseProductVersion` reads a retained
`sw_vers` capture without executing a command.

`Detect(ctx)` reads `kern.osproductversion` through the typed `x/sys` libSystem
wrapper on macOS. On Linux and Windows there is no native macOS version to detect;
callers provide their compatibility target explicitly. All parsing, comparison
and target selection work identically on all three systems. Production code
uses neither subprocesses nor cgo.

A product version is not a Darwin kernel release, Xcode/SDK version, build number
or filesystem property. For example, compression's `MNT_CPROTECT` policy comes
from the observed volume flags, independently of the OS profile.

## Behavior qualification

Recognising a version does not establish feature parity. Each feature owns its
behavior selection and evidence; this package does not substitute guessed policy
for a missing native capture. The compression capture selects a complete native
trace profile by product version, keeping macOS 26's `open` and macOS 27's
`openat` acquisition observations separate. Quarantine also uses the shared
version parser, while its currently qualified behavior profiles remain 26/27.

Outstanding work:

- Complete on-runner qualification of the macOS 15 resource-fork opening route
  against its retained C controls. Recompression profiles now retain 330 cases
  per release, and resource-fork opening profiles retain 180 cases per release.
- Qualify macOS 15 quarantine codecs, process state and file operations before
  implementing its behavior route; do not alias it to a newer release.
- Audit remaining framework/CLI behavior differences and thread explicit target
  versions through APFS metadata operations and downstream codesign APIs.
- Retain native evidence for any minor/patch divergence rather than treating a
  major-version profile as a universal compatibility guarantee.

The portable CI gate requires over 95% coverage for each source file and the
complete package, mandatory test suites without skips, raw test output and source
hashes. Native detection is independently checked against `sw_vers`. Existing
compression capture checks remain in place, with a macOS 15 job added for the
older release's qualification.
