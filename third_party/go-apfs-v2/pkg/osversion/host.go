package osversion

import "context"

func detect(ctx context.Context, read func() (string, error)) (Version, error) {
	if err := ctx.Err(); err != nil {
		return Version{}, err
	}
	value, err := read()
	if err != nil {
		return Version{}, err
	}
	if err = ctx.Err(); err != nil {
		return Version{}, err
	}
	return Parse(value)
}
