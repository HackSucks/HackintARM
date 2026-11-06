package hostdata

import (
	"context"
	"errors"
	"io"
	"os"
)

// Run every cleanup step even if an earlier one failed. A missing private name
// is harmless after commit or partially failed preparation; other errors remain.
func cleanupReplacement(steps ...func() error) (err error) {
	for _, step := range steps {
		e := step()
		if !os.IsNotExist(e) { // A joined missing-name plus another failure must survive.
			err = errors.Join(err, e)
		}
	}
	return err
}
func replacementStep(ctx context.Context, step func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := step()
	if canceled := ctx.Err(); canceled != nil {
		return errors.Join(err, canceled)
	}
	return err
}
func replacementValue[T any](ctx context.Context, step func() (T, error)) (value T, err error) {
	if err = ctx.Err(); err != nil {
		return value, err
	}
	value, err = step()
	if canceled := ctx.Err(); canceled != nil {
		return value, errors.Join(err, canceled)
	}
	return value, err
}

type replacementReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r replacementReader) Read(p []byte) (int, error) {
	return replacementValue(r.ctx, func() (int, error) { return r.reader.Read(p) })
}

type replacementWriter struct {
	ctx    context.Context
	writer io.Writer
}

func (w replacementWriter) Write(p []byte) (int, error) {
	return replacementValue(w.ctx, func() (int, error) { return w.writer.Write(p) })
}

// Keep an auxiliary held directory until all dependent native work finishes.
// Failure to close it also invalidates any returned replacement capability.
func replacementWithHandle(ctx context.Context, open func() (*os.File, error), use func(*os.File) (*os.File, error)) (file *os.File, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	held, err := open()
	if err != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	defer func() {
		err = errors.Join(err, held.Close(), ctx.Err())
		if err != nil && file != nil {
			err = errors.Join(err, file.Close())
			file = nil
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return use(held)
}

func replacementOpenAfterClone(cloned bool, chmod func() error, open func(bool) (*os.File, error)) (*os.File, error) {
	if cloned {
		if err := chmod(); err != nil {
			return nil, err
		}
	}
	return open(cloned)
}
