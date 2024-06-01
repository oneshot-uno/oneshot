package itest

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

type PortPool struct {
	sync.Mutex
	used  map[string]struct{}
	start int
	end   int
}

func (pr *PortPool) Get() string {
	pr.Lock()
	defer pr.Unlock()

	if pr.used == nil {
		pr.used = make(map[string]struct{})
	}

	for i := pr.start; i < pr.end; i++ {
		port := strconv.Itoa(i)
		if _, ok := pr.used[port]; !ok {
			pr.used[port] = struct{}{}
			return port
		}
	}

	panic("no available ports")
}

var oneshotPortPool = &PortPool{
	start: 8080,
	end:   65535,
}

type Oneshot struct {
	T          *testing.T
	Env        []string
	Args       []string
	Files      FilesMap
	Stdin      io.Reader
	Stdout     io.Writer
	Stderr     io.Writer
	WorkingDir string
	Port       string

	Cmd       *exec.Cmd
	stdoutBuf *bytes.Buffer
	stderrBuf *bytes.Buffer
}

func (o *Oneshot) Cleanup() {}

func (o *Oneshot) Start() {
	if o.Files != nil {
		o.Files.ProjectInto(o.WorkingDir)
	}

	if o.Stdout == nil {
		o.stdoutBuf = bytes.NewBuffer(nil)
		o.Stdout = o.stdoutBuf
	}

	if o.Stderr == nil {
		o.stderrBuf = bytes.NewBuffer(nil)
		o.Stderr = o.stderrBuf
	}

	// find "port" in the args and replace the following arg with the port
	setPort := false
	for i, arg := range o.Args {
		if (arg == "--port" || arg == "-p") && i+1 < len(o.Args) {
			o.Args[i+1] = o.Port
			setPort = true
			break
		}
	}
	if !setPort {
		o.Args = append(o.Args, "--port", o.Port)
	}

	if o.Cmd == nil {
		o.Cmd = exec.Command(
			filepath.Join(o.WorkingDir, "../../oneshot.testing"),
			o.Args...,
		)
		o.Cmd.Stdin = o.Stdin
		o.Cmd.Stdout = o.Stdout
		o.Cmd.Stderr = o.Stderr
		o.Cmd.Dir = o.WorkingDir
		o.Cmd.Env = append(os.Environ(), o.Env...)
	}

	if err := o.Cmd.Start(); err != nil {
		o.T.Fatalf("unable to start oneshot exec: %v\n", err)
	}

	time.Sleep(time.Second)
}

func (o *Oneshot) Wait() {
	if o.Cmd == nil {
		o.T.Fatal("attempting to exit oneshot but oneshot it not running")
	}
	o.Cmd.Wait()
}

func (o *Oneshot) Signal(sig os.Signal) {
	if o.Cmd != nil {
		o.Cmd.Process.Signal(sig)
	}
}
