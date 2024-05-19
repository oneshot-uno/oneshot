package file

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func tarball(compress bool, paths []string, w io.Writer) error {
	var tw *tar.Writer
	if compress {
		gw := gzip.NewWriter(w)
		defer gw.Close()
		tw = tar.NewWriter(gw)
	} else {
		tw = tar.NewWriter(w)
	}
	defer tw.Close()

	formatName := func(name string) string {
		// needed for windows
		name = strings.ReplaceAll(name, `\`, `/`)
		if string(name[0]) == `/` {
			name = name[1:]
		}
		return name
	}

	walkFunc := func(path string, buf []byte) func(string, os.FileInfo, error) error {
		dir := filepath.Dir(path)
		return func(fp string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			var link string

			if info.Mode()&os.ModeSymlink != 0 {
				link, err = os.Readlink(fp)
				if err != nil {
					return fmt.Errorf("failed to read symlink %s: %w", fp, err)
				}
			}

			header, err := tar.FileInfoHeader(info, link)
			if err != nil {
				return err
			}

			header.Name = strings.TrimPrefix(fp, dir)
			header.Name = formatName(header.Name)

			if header.Name == "" {
				return nil
			}

			if err = tw.WriteHeader(header); err != nil {
				return err
			}

			if !info.Mode().IsRegular() {
				return nil
			}

			fh, err := os.Open(fp)
			if err != nil {
				return err
			}
			defer fh.Close()

			if _, err = io.CopyBuffer(tw, fh, buf); err != nil {
				return err
			}

			return nil
		}
	}

	// Loop over files to be archived
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() { // Archiving a directory; needs to be walked
			buf := make([]byte, 32*1024)
			err := filepath.Walk(path, walkFunc(path, buf))
			if err != nil {
				return err
			}
		} else { // Archiving a single file or symlink
			size := info.Size()
			if size == 0 {
				size = 32 * 1024
			}
			buf := make([]byte, size)
			if err = walkFunc(path, buf)(path, info, nil); err != nil {
				return err
			}
		}
	}

	return nil
}
