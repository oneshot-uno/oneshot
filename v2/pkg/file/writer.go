package file

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/forestnode-io/oneshot/v2/pkg/events"
	"github.com/forestnode-io/oneshot/v2/pkg/log"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
)

type WriteTransferConfig struct {
	userProvidedName string
	dir              string

	w io.WriteCloser
}

func NewWriteTransferConfig(ctx context.Context, location string) (*WriteTransferConfig, error) {
	var wtc WriteTransferConfig
	// if we are receiving to stdout
	if location == "" {
		output.ReceivingToStdout(ctx)
		// and are outputting json
		if format, _ := output.GetFormatAndOpts(ctx); format == "json" {
			// send the contents into the ether.
			// there's a buffer elsewhere that will provide the contents in the json object.
			wtc.w = null{}
		} else {
			// otherwise write the content to stdout
			wtc.w = output.GetBufferedWriteCloser(ctx)
		}
		return &wtc, nil
	}

	var err error
	location, err = filepath.Abs(location)
	if err != nil {
		return nil, err
	}

	// get info on user provided location
	stat, err := os.Stat(location)
	// if location doesn't exist
	if err != nil {
		// then the user wants to receive to a file that doesn't exist yet and has given
		// us the file and directory names all in 1 string
		wtc.dir, wtc.userProvidedName = filepath.Split(location)
	} else {
		// otherwise, the user either wants to receive to an existing directory and
		// hasn't given us the name of the file they want to receive to
		if stat.IsDir() {
			// so we can only set the directory name
			wtc.dir = location
		} else {
			// or the user wants to overwrite an existing file
			wtc.dir, wtc.userProvidedName = filepath.Split(location)
		}
	}

	// make sure we can write to the directory we're receiving to
	if err = isDirWritable(wtc.dir); err != nil {
		return nil, err
	}

	return &wtc, nil
}

type WriteTransferSession struct {
	ctx context.Context

	Progress atomic.Int64
	w        io.WriteCloser
}

func (w *WriteTransferConfig) NewWriteTransferSession(ctx context.Context, name, mime string) (*WriteTransferSession, error) {
	if w.w != nil {
		return &WriteTransferSession{
			ctx: ctx,
			w:   w.w,
		}, nil
	}

	var (
		err error
		ts  = WriteTransferSession{ctx: ctx}
	)

	fileName := w.userProvidedName
	if fileName == "" {
		fileName = name
	}
	if fileName == "" {
		fileName, err = randName(mime)
		if err != nil {
			return nil, err
		}
	}

	path := filepath.Join(w.dir, fileName)
	if ts.w, err = os.Create(path); err != nil {
		return nil, err
	}

	return &ts, nil
}

func (ts *WriteTransferSession) Write(p []byte) (int, error) {
	n, err := ts.w.Write(p)
	ts.Progress.Add(int64(n))
	return n, err
}

func (ts *WriteTransferSession) Close() error {
	log := log.Logger()
	err := ts.w.Close()
	if !events.Succeeded(ts.ctx) {
		if file, ok := ts.w.(*os.File); ok && file != nil {
			if file != os.Stdout {
				if err = os.Remove(file.Name()); err != nil {
					log.Error().Err(err).
						Str("file", file.Name()).
						Msg("error removing file")
				}
			}
		}
	}
	return err
}

func (ts *WriteTransferSession) Path() string {
	if file, ok := ts.w.(*os.File); ok && file != nil {
		if file != os.Stdout {
			return file.Name()
		}
	}

	return ""
}

func randName(mimeType string) (string, error) {
	name := fmt.Sprintf("%0-x", rand.Int31())
	if mimeType != "" {
		// use it get the appropriate file extension
		exts, err := mime.ExtensionsByType(mimeType)
		if err != nil {
			return "", err
		}
		if len(exts) > 0 {
			name += exts[0]
		}
	}
	return name, nil
}

func isDirWritable(path string) error {
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}

	return _isDirWritable(path, info)
}

// null is a noop io.WriteCloser
type null struct{}

func (null) Write(p []byte) (int, error) {
	return len(p), nil
}

func (null) Close() error {
	return nil
}
