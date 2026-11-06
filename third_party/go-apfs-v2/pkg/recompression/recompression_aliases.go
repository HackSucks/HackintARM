package recompression

import (
	"cmp"
	"context"
	"errors"
	"reflect"
	"slices"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/pkg/metatransport"
)

type recompressionAlias struct {
	file        recompressionPayloadFile
	record      metatransport.Record
	baseline    metatransport.BlobRef
	copyPayload bool
}

func (a recompressionAlias) Close() error { return a.file.Close() }

func recompressionAliases(ctx context.Context, s carrier, m metatransport.Manifest, index int, original metatransport.Record, baseline metatransport.BlobRef, updated metatransport.Record, allowChanged bool) (aliases []recompressionAlias, err error) {
	if original.LinkGroup == "" {
		return nil, nil
	}
	defer func() {
		if err != nil {
			for _, a := range aliases {
				err = errors.Join(err, a.Close())
			}
			aliases = nil
		}
	}()
	for i, r := range m.Records {
		if i == index || r.LinkGroup != original.LinkGroup {
			continue
		}
		if r.Kind != "file" || r.MaterializedKind != "file" || r.Payload == nil || !reflect.DeepEqual(recompressionAliasState(r), recompressionAliasState(original)) {
			return aliases, metatransport.ErrConflict
		}
		file, e := s.OpenPayload(ctx, r.Materialized)
		if e != nil {
			return aliases, e
		}
		ref, e := metatransport.PayloadReference(ctx, file)
		if e != nil {
			return aliases, errors.Join(e, file.Close())
		}
		if ref != baseline && (!allowChanged || ref != *r.Payload) {
			return aliases, errors.Join(metatransport.ErrConflict, file.Close())
		}
		aliases = append(aliases, recompressionAlias{file: file, record: r, baseline: ref, copyPayload: ref != baseline})
		r.Attributes, r.AppleDouble, r.Payload = updated.Attributes, updated.AppleDouble, updated.Payload
		r.Darwin.Mode, r.Darwin.Flags = updated.Darwin.Mode, updated.Darwin.Flags
		r.Darwin.Modify, r.Darwin.Access = updated.Darwin.Modify, updated.Darwin.Access
		r.Darwin.Change = updated.Darwin.Change
		m.Records[i] = r
	}
	return aliases, nil
}

func recompressionAliasState(r metatransport.Record) metatransport.Record {
	r.Original, r.Materialized = "", ""
	r.NativeAttributes = nil
	r.NativeCaptured, r.NativeUnsupported = false, false
	r.Attributes = slices.Clone(r.Attributes)
	slices.SortFunc(r.Attributes, func(a, b metatransport.Attribute) int { return cmp.Compare(a.Name, b.Name) })
	for _, value := range []**time.Time{&r.Darwin.Birth, &r.Darwin.Modify, &r.Darwin.Change, &r.Darwin.Access} {
		if *value != nil {
			v := (*value).UTC()
			*value = &v
		}
	}
	return r
}
