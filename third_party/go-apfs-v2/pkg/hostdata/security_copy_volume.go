package hostdata

// SecurityCopyVolume identifies an endpoint of a security copy. The provider
// must bind it to the same source or destination used by the copy operation.
type SecurityCopyVolume string

const (
	SecurityCopySourceVolume      SecurityCopyVolume = "source"
	SecurityCopyDestinationVolume SecurityCopyVolume = "destination"
)

// SecurityCopyVolumePolicy captures whether an endpoint's volume positively
// has Darwin MNT_NOSUID semantics. False with nil error is an observed negative;
// any error means unknown, even if the returned boolean is true. Native
// copyfile continues after a query error; VolumeQueries retains that error so
// callers can distinguish completion from fully observed policy.
//
// Calls occur after ACL selection and before writes, source before destination.
// No query occurs without Stat, with AlwaysCopySetID or ForbidCopySetID, or after
// an earlier fatal capture/selection error. A positive source result skips the
// destination. A failed source query still permits a destination query.
//
// Implementations can use held host handles or captured foreign mount state on
// every OS. APFS/HFS+ bytes alone cannot establish this runtime mount policy.
// Implementations must not mutate the copy's source, target or tree.
type SecurityCopyVolumePolicy interface {
	NoSetID(SecurityCopyVolume) (bool, error)
}

// SecurityCopyVolumeQuery records one attempted lookup. NoSetID is meaningful
// only when Err is nil; on error it is always false. Missing entries represent
// unqueried endpoints, not observed negatives. Err retains the original cause.
type SecurityCopyVolumeQuery struct {
	Volume  SecurityCopyVolume
	NoSetID bool
	Err     error
}

func securityCopyNoSetID(options SecurityCopyOptions, result *SecurityCopyResult) bool {
	if !options.Stat || options.AlwaysCopySetID {
		return false
	}
	if options.ForbidCopySetID {
		return true
	}
	if options.VolumePolicy == nil {
		return options.SourceNoSetID || options.DestinationNoSetID
	}
	for _, volume := range []SecurityCopyVolume{SecurityCopySourceVolume, SecurityCopyDestinationVolume} {
		noSetID, err := options.VolumePolicy.NoSetID(volume)
		if err != nil {
			noSetID = false
		}
		result.VolumeQueries = append(result.VolumeQueries, SecurityCopyVolumeQuery{Volume: volume, NoSetID: noSetID, Err: err})
		if noSetID {
			return true
		}
	}
	return false
}
