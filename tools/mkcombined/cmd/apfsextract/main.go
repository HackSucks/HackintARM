// apfsextract recursively copies a directory out of an APFS volume, for
// offline diagnostics (e.g. the unified log's uuidtext/DSC files).
//
//	go run ./cmd/apfsextract <image> <volume> <src> <dst>
package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: apfsextract <image> <volume> <src> <dst>")
		os.Exit(2)
	}
	img, sel, src, dst := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	c, closer, err := apfs.OpenImage(img, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apfsextract:", err)
		os.Exit(1)
	}
	defer closer.Close()

	v, err := c.VolumeBySelector(sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apfsextract:", err)
		os.Exit(1)
	}

	n := 0
	var walk func(sp, dp string) error
	walk = func(sp, dp string) error {
		des, err := v.ReadDir(sp)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(dp, 0o755); err != nil {
			return err
		}
		for _, de := range des {
			name := de.Name()
			csp := path.Join(sp, name)
			cdp := filepath.Join(dp, name)
			fi, err := de.Info()
			if err != nil {
				fmt.Fprintln(os.Stderr, "skip", csp, err)
				continue
			}
			if fi.IsDir() {
				if err := walk(csp, cdp); err != nil {
					return err
				}
				continue
			}
			data, err := v.ReadFile(csp)
			if err != nil {
				fmt.Fprintln(os.Stderr, "skip", csp, err)
				continue
			}
			if err := os.WriteFile(cdp, data, 0o644); err != nil {
				return err
			}
			n++
		}
		return nil
	}
	if err := walk(src, dst); err != nil {
		fmt.Fprintln(os.Stderr, "apfsextract:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "apfsextract: %d files\n", n)
}