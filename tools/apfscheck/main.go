package main

import (
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v2/pkg/apfs"
)

type walker struct {
	vol       *apfs.Volume
	bad       int
	checked   int
	verbose   bool
}

func (w *walker) children(dir string) {
	des, err := w.vol.ReadDir(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: readdir: %v\n", dir, err)
		return
	}
	for _, de := range des {
		name := de.Name()
		full := name
		if dir != "." {
			full = dir + "/" + name
		}
		info, err := de.Info()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: info: %v\n", full, err)
			continue
		}
		mode := info.Mode()
		switch {
		case mode.IsDir():
			w.children(full)
		case mode.IsRegular():
			vals, _ := w.vol.XattrValues(full)
			if _, compressed := vals["com.apple.decmpfs"]; compressed {
				continue
			}
			if info.Size() <= 0 {
				continue
			}
			f, err := w.vol.Open(full)
			if err != nil {
				fmt.Printf("OPENFAIL %s size=%d: %v\n", full, info.Size(), err)
				w.bad++
				continue
			}
			ra, ok := f.(io.ReaderAt)
			if !ok {
				fmt.Printf("NOTREADERAT %s size=%d\n", full, info.Size())
				w.bad++
				continue
			}
			buf := make([]byte, 1)
			n, err := ra.ReadAt(buf, 0)
			w.checked++
			if err != nil || n == 0 {
				fmt.Printf("BADREAD %s size=%d n=%d err=%v\n", full, info.Size(), n, err)
				w.bad++
			}
		}
	}
}

func main() {
	img := os.Args[1]
	c, closer, err := apfs.OpenImage(img, nil)
	if err != nil {
		panic(err)
	}
	defer closer.Close()
	vol, err := c.VolumeBySelector("0")
	if err != nil {
		panic(err)
	}
	w := &walker{vol: vol}
	w.children(".")
	fmt.Printf("--- %s: checked=%d bad=%d\n", img, w.checked, w.bad)
}
