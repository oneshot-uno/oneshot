package file

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sync/atomic"

	"github.com/mattn/go-isatty"
)

type ReadTransferSession struct {
	r        io.ReadCloser
	Progress atomic.Int64
	Size     func() (int64, error)
}

func (rts *ReadTransferSession) Read(p []byte) (int, error) {
	n, err := rts.r.Read(p)
	rts.Progress.Add(int64(n))
	return n, err
}

func (rts *ReadTransferSession) Close() error {
	return rts.r.Close()
}

func isReadable(path string) error {
	f, err := os.Open(path)
	if err == nil {
		f.Close()
	}
	return err
}

// bufferedStdinReader reads all of stdin when Read is first called and buffers it.
// Subsequent reads come from the buffer, not stdin.
type bufferedStdinReader struct {
	buf  []byte
	prog int
	size int
}

func (b *bufferedStdinReader) Read(p []byte) (int, error) {
	var err error

	if b.buf == nil {
		b.buf, err = io.ReadAll(os.Stdin)
		if err != nil {
			return 0, err
		}
		b.size = len(b.buf)
	}

	b.prog += copy(p, (b.buf)[b.prog:])
	if b.size <= b.prog {
		err = io.EOF
	}

	return b.prog, err
}

func (b *bufferedStdinReader) Close() error {
	return nil
}

type ReadTransferConfig interface {
	NewReaderTransferSession(context.Context) (*ReadTransferSession, error)
}

func IsTTY(rtc ReadTransferConfig) bool {
	_, ok := rtc.(*stdinTTYReaderConfig)
	return ok
}

func IsArchive(rtc ReadTransferConfig) bool {
	_, ok := rtc.(*archiveReaderConfig)
	return ok
}

func NewReadTransferConfig(archiveFormat string, locations ...string) (ReadTransferConfig, error) {
	var rc ReadTransferConfig
	// determine what we're sending and what needs to be archived
	switch len(locations) {
	case 0: // transferring from stdin
		if isatty.IsTerminal(os.Stdin.Fd()) || os.Getenv("ONESHOT_TESTING_TTY_STDIN") != "" {
			rc = &stdinTTYReaderConfig{}
		} else {
			// could be either a file or pipe
			stat, err := os.Stdin.Stat()
			if err != nil {
				return nil, err
			}
			if isPipe := stat.Mode()&fs.ModeNamedPipe != 0; isPipe {
				buf, err := io.ReadAll(os.Stdin)
				if err != nil {
					return nil, err
				}
				rc = &stdinPipeReaderConfig{
					buf: buf,
				}
			} else {
				rc = &stdinFileReaderConfig{}
			}
		}
	case 1: // transferring a single path
		//need to check if its a dir; if so, archive it into a single file
		location := locations[0]
		stat, err := os.Stat(location)
		if err != nil {
			return nil, err
		}

		if err := isReadable(location); err != nil {
			return nil, err
		}

		if stat.IsDir() {
			rc = &archiveReaderConfig{
				format: archiveFormat,
				paths:  locations,
			}
		} else {
			rc = &fileReaderConfig{
				path: location,
			}
		}
	default: // transferring multiple paths
		// doesn't matter if each one is a file or a dir, archive them all into a single file
		for _, location := range locations {
			if err := isReadable(location); err != nil {
				return nil, err
			}
		}
		rc = &archiveReaderConfig{
			format: archiveFormat,
			paths:  locations,
		}
	}

	return rc, nil
}

// fileReaderConfig defaults to not buffering its input
type fileReaderConfig struct {
	path string
}

func (c *fileReaderConfig) NewReaderTransferSession(ctx context.Context) (*ReadTransferSession, error) {
	var rts ReadTransferSession
	file, err := os.Open(c.path)
	if err != nil {
		return nil, err
	}
	rts.r = file

	rts.Size = func() (int64, error) {
		stat, err := file.Stat()
		if err != nil {
			return 0, err
		}
		return stat.Size(), nil
	}

	return &rts, nil
}

// fileReaderConfig defaults to lazy-buffering its input under a certain size
type archiveReaderConfig struct {
	format string
	paths  []string
	buf    []byte
}

func (c *archiveReaderConfig) NewReaderTransferSession(ctx context.Context) (*ReadTransferSession, error) {
	if c.buf == nil {
		r, w := io.Pipe()
		go func() {
			var err error
			switch c.format {
			case "zip":
				err = zip(c.paths, w)
			case "tar":
				err = tarball(false, c.paths, w)
			default:
				err = tarball(true, c.paths, w)
			}
			if err != nil {
				//TODO: don't panic
				panic(err)
			}
			w.Close()
		}()
		return &ReadTransferSession{
			r: r,
			Size: func() (int64, error) {
				return 0, fmt.Errorf("NA")
			},
		}, nil
	}

	buf := bytes.NewBuffer(c.buf)
	switch c.format {
	case "zip":
		if err := zip(c.paths, buf); err != nil {
			return nil, err
		}
	case "tar":
		if err := tarball(false, c.paths, buf); err != nil {
			return nil, err
		}
	default:
		if err := tarball(true, c.paths, buf); err != nil {
			return nil, err
		}
	}

	return &ReadTransferSession{
		r: io.NopCloser(buf),
		Size: func() (int64, error) {
			return int64(buf.Len()), nil
		},
	}, nil
}

// stdinTTYReaderConfig defaults to lazy-buffering its input
type stdinTTYReaderConfig struct {
	r *bufferedStdinReader
}

func (c *stdinTTYReaderConfig) NewReaderTransferSession(ctx context.Context) (*ReadTransferSession, error) {
	c.r = &bufferedStdinReader{}
	rts := ReadTransferSession{
		r: c.r,
		Size: func() (int64, error) {
			return 0, fmt.Errorf("NA")
		},
	}
	return &rts, nil
}

// stdinFileReaderConfig defaults to lazy-buffering its input
type stdinFileReaderConfig struct{}

func (c *stdinFileReaderConfig) NewReaderTransferSession(ctx context.Context) (*ReadTransferSession, error) {
	var rts ReadTransferSession
	rts.r = &bufferedStdinReader{}
	rts.Size = func() (int64, error) {
		stat, err := os.Stdin.Stat()
		if err != nil {
			return 0, err
		}

		return stat.Size(), nil
	}
	return &rts, nil
}

// stdinPipeReaderConfig defaults to pre-buffering its input
type stdinPipeReaderConfig struct {
	buf []byte
}

func (c *stdinPipeReaderConfig) NewReaderTransferSession(ctx context.Context) (*ReadTransferSession, error) {
	if c.buf != nil {
		return &ReadTransferSession{
			r: io.NopCloser(bytes.NewReader(c.buf)),
			Size: func() (int64, error) {
				return int64(len(c.buf)), nil
			},
		}, nil
	}
	return &ReadTransferSession{
		r: &bufferedStdinReader{},
		Size: func() (int64, error) {
			return 0, fmt.Errorf("NA")
		},
	}, nil
}
