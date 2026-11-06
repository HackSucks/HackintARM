package appledouble

// QuarantineUpdate is one ordered quarantine application decision. RecordIndex
// identifies the record in File.Attrs. A non-nil Quarantine requests application;
// nil with Invalid means native parsing ignored that record. SourceOverride
// means source quarantine state supplied the value instead of the record bytes.
//
// Decisions retain their positions relative to other attributes. They describe
// which values to apply, not destination flag/timestamp/agent normalization or
// copyfile's preceding destination-xattr removal pass.
type QuarantineUpdate struct {
	RecordIndex    int
	Quarantine     *Quarantine
	Invalid        bool
	SourceOverride bool
}

// QuarantineUpdates selects quarantine values in record order for the target
// profile. Every matching record is processed, including zero-length records.
// Malformed records are ignored individually; they do not erase earlier valid
// decisions. An optional, already-resolved source state overrides every matching
// record, even an empty or malformed one. With no matching records there are no
// application decisions, including when source state is supplied.
//
// Unknown profiles or invalid source models return ErrQuarantine. Resolving the
// source/carrier state, preparing the destination, applying each decision at its
// record position and handling write failures belong to metadata transport.
// Returned values do not alias the source model, record storage or each other.
func (f *File) QuarantineUpdates(profile QuarantineProfile, source *Quarantine) ([]QuarantineUpdate, error) {
	if _, err := profile.maxFlags(); err != nil {
		return nil, err
	}
	if source != nil {
		if _, err := source.MarshalBinaryWithProfile(profile); err != nil {
			return nil, err
		}
	}
	if f == nil {
		return nil, nil
	}
	var updates []QuarantineUpdate
	for i, attr := range f.Attrs {
		if attr.Name != QuarantineName {
			continue
		}
		update := QuarantineUpdate{RecordIndex: i, SourceOverride: source != nil}
		if source != nil {
			value := *source
			if value.Flags == 0 {
				value.Flags = 1
			}
			update.Quarantine = &value
		} else {
			value, err := ParseQuarantineWithProfile(attr.Value, profile)
			update.Quarantine = value
			update.Invalid = err != nil
		}
		updates = append(updates, update)
	}
	return updates, nil
}
