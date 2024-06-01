package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	itest "github.com/forestnode-io/oneshot/v2/integration_testing"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/suite"
)

var withoutInternet = flag.Bool("without-internet", false, "skip tests that require internet access")

func TestBasicTestSuite(t *testing.T) {
	suite.Run(t, new(ts))
}

type ts struct {
	itest.TestSuite
}

func (suite *ts) Test_FROM_StdinTTY_TO_ANY__StdoutTTY_StdoutErrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send"}
	oneshot.Stdin = itest.EOFReader([]byte("SUCCESS"))
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get("http://127.0.0.1:" + oneshot.Port)
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()

	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_FROM_StdinTTY_TO_ANY__StdoutNONTTY_StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send"}
	oneshot.Stdin = itest.EOFReader([]byte("SUCCESS"))
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get("http://127.0.0.1:" + oneshot.Port)
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().NotContains(string(stdout), "\x1b")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
	suite.Assert().Contains(string(stderr), "success\n")
}

func (suite *ts) Test_FROM_File_TO_ANY__StdoutTTY_StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "./test.txt"}
	oneshot.Files = itest.FilesMap{"./test.txt": []byte("SUCCESS")}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
	suite.Assert().Contains(string(stderr), "success\n\x1b[?25h")
}

func (suite *ts) Test_FROM_File_TO_ANY__StdoutNONTTY_StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "./test.txt"}
	oneshot.Files = itest.FilesMap{"./test.txt": []byte("SUCCESS")}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()
	// expect dynamic output to have gone to stderr but static output goes to stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().NotContains(string(stdout), "\x1b")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Contains(string(stderr), "success\n\x1b[?25h")
}

func (suite *ts) Test_FROM_File_TO_ANY__StdoutNONTTY_StderrNONTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "./test.txt"}
	oneshot.Files = itest.FilesMap{"./test.txt": []byte("SUCCESS")}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()
	// expect no dynamic out, only static outpu ton stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().NotContains(string(stdout), "\x1b")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
	suite.Assert().Contains(string(stderr), "success\n")
}

func (suite *ts) Test_FROM_File_TO_ANY__JSON() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "--output", "json", "./test.txt"}
	oneshot.Files = itest.FilesMap{"./test.txt": []byte("SUCCESS")}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/?q=1", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusOK)

	body, err := io.ReadAll(resp.Body)
	suite.Assert().NoError(err)
	resp.Body.Close()
	suite.Assert().Equal(string(body), "SUCCESS")

	oneshot.Wait()
	// expect no dynamic out, only static output on stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	var report output.Report
	err = json.Unmarshal(stdout, &report)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(report.Success)
	suite.Assert().Equal(0, len(report.Attempts))

	req := report.Success.Request
	suite.Require().Equal("GET", req.Method)
	suite.Require().Equal("HTTP/1.1", req.Protocol)
	suite.Require().Equal(map[string][]string{
		"Accept-Encoding": {"gzip"},
		"User-Agent":      {"Go-http-client/1.1"},
	}, req.Header)
	suite.Require().Equal(fmt.Sprintf("127.0.0.1:%s", oneshot.Port), req.Host)
	suite.Require().Empty(req.Trailer)
	suite.Require().NotEmpty(req.RemoteAddr)
	suite.Require().Equal("/?q=1", req.RequestURI)
	suite.Require().Equal("/", req.Path)
	suite.Require().Equal(map[string][]string{
		"q": {"1"},
	}, req.Query)

	file := report.Success.File
	now := time.Now()
	suite.Require().Equal(len("SUCCESS"), int(file.Size))
	suite.Require().Equal(file.Size, file.TransferSize)
	suite.Require().WithinDuration(now, file.TransferStartTime, 5*time.Second)
	suite.Require().WithinDuration(now, file.TransferEndTime, 5*time.Second)
	suite.Require().Less(time.Duration(0), file.TransferDuration)
	suite.Require().Nil(file.Content)
	suite.Require().Empty(file.Name)
	suite.Require().Empty(file.Path)
	suite.Require().Empty(file.MIME)

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_StatusCode() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "--status-code", "418"}
	oneshot.Stdin = itest.EOFReader([]byte("SUCCESS"))
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDIN=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(resp.StatusCode, http.StatusTeapot)
}

func (suite *ts) Test_Send_Directory_targz() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "./testDir"}
	oneshot.Files = itest.FilesMap{
		"./testDir/testDir1/testDir1_1/test.txt":  []byte("SUCCESS"),
		"./testDir/testDir1/testDir1_1/test2.txt": []byte("SUCCESS2"),
		"./testDir/testDir1/testDir1_2/test3.txt": []byte("SUCCESS3"),
		"./testDir/testDir1/testDir1_2/test4.txt": []byte("SUCCESS4"),
		"./testDir/testDir2/testDir2_1/test5.txt": []byte("SUCCESS5"),
		"./testDir/testDir2/testDir2_1/test6.txt": []byte("SUCCESS6"),
		"./testDir/testDir2/testDir2_2/test7.txt": []byte("SUCCESS7"),
		"./testDir/testDir3/test8.txt":            []byte("SUCCESS"),
		"./testDir/testDir/test9.txt":             []byte("SUCCESS2"),
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	tarFileName := filepath.Join(suite.TestDir, "test.tar.gz")
	bufBytes, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	err = os.WriteFile(tarFileName, bufBytes, 0600)
	suite.Require().NoError(err)

	tarOut, err := exec.Command("tar", "-xzf", tarFileName, "-C", suite.TestDir).CombinedOutput()
	suite.Require().NoError(err, string(tarOut))

	for name, content := range oneshot.Files {
		path := filepath.Join(suite.TestDir, name[2:])
		fileBytes, err := os.ReadFile(path)
		suite.Require().NoError(err)
		suite.Assert().Equal(string(content), string(fileBytes))
	}

	oneshot.Wait()
}

func (suite *ts) Test_Send_Oneshot_Directory_targz() {
	if *withoutInternet {
		suite.T().Skip("skipping test that requires internet access")
	}

	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "./oneshot"}

	oneshotRepoPath := filepath.Join(oneshot.WorkingDir, "oneshot")

	_, err := git.PlainClone(oneshotRepoPath, false, &git.CloneOptions{
		URL:   "https://github.com/forestnode-io/oneshot",
		Depth: 1,
	})
	suite.Require().NoError(err)

	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	oneshotCopyTarPath := filepath.Join(oneshot.WorkingDir, "oneshot-copy.tar.gz")
	oneshotCopyTarFile, err := os.Create(oneshotCopyTarPath)
	suite.Require().NoError(err)
	defer oneshotCopyTarFile.Close()
	_, err = io.Copy(oneshotCopyTarFile, resp.Body)
	suite.Require().NoError(err)

	oneshotCopyPath := filepath.Join(oneshot.WorkingDir, "oneshot-copy")
	err = os.Mkdir(oneshotCopyPath, 0700)
	suite.Require().NoError(err)

	tarOut, err := exec.Command("tar", "-xzf", oneshotCopyTarPath, "-C", oneshotCopyPath).CombinedOutput()
	suite.Require().NoError(err, string(tarOut))

	diffOut, err := exec.Command("diff", "-qr", oneshotRepoPath, filepath.Join(oneshotCopyPath, "oneshot")).CombinedOutput()
	suite.Require().NoError(err, string(diffOut))

	oneshot.Wait()
}

func (suite *ts) Test_Send_Directory_zip() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send", "-a", "zip", "./testDir"}
	oneshot.Files = itest.FilesMap{
		"./testDir/test.txt":  []byte("SUCCESS"),
		"./testDir/test2.txt": []byte("SUCCESS2"),
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
	suite.Require().NoError(err)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)

	bufBytes, err := io.ReadAll(resp.Body)
	suite.Require().NoError(err)
	bodyBuf := bytes.NewReader(bufBytes)

	zr, err := zip.NewReader(bodyBuf, resp.ContentLength)
	suite.Require().NoError(err)

	files := map[string]string{
		"testDir/test.txt":  "",
		"testDir/test2.txt": "",
	}
	for _, f := range zr.File {
		fc, err := f.Open()
		suite.Require().NoError(err)
		if _, ok := files[f.Name]; ok {
			content := make([]byte, f.UncompressedSize64)
			_, err = fc.Read(content)
			if errors.Is(err, io.EOF) {
				err = nil
			}
			suite.Require().NoError(err)
			files[f.Name] = string(content)
		} else {
			suite.Fail("unexpected file in zip", f.Name)
		}
	}

	for name, content := range oneshot.Files {
		zContent, ok := files[filepath.Clean(name)]
		suite.Require().True(ok)
		suite.Assert().Equal(string(content), zContent)
	}

	oneshot.Wait()
}

func (suite *ts) Test_MultipleClients() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"send"}
	oneshot.Stdin = io.LimitReader(rand.Reader, 1<<15)
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	m := sync.Mutex{}
	c := sync.NewCond(&m)

	responses := make(chan int, runtime.NumCPU())
	wg := sync.WaitGroup{}
	for i := 1; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func(index int) {
			c.L.Lock()
			c.Wait()
			c.L.Unlock()

			resp, _ := http.Get(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port))
			if resp != nil {
				if resp.Body != nil {
					resp.Body.Close()
				}
				responses <- resp.StatusCode
			} else {
				responses <- 0
			}
			wg.Done()
		}(i)
	}
	time.Sleep(500 * time.Millisecond)
	c.L.Lock()
	c.Broadcast()
	c.L.Unlock()

	wg.Wait()
	close(responses)

	oks := 0
	gones := 0
	for code := range responses {
		if code == 200 {
			oks++
		} else if code == http.StatusGone {
			gones++
		}
	}
	suite.Assert().Equal(1, oks)
	suite.Assert().Equal(runtime.NumCPU()-2, gones)

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
	suite.Assert().Contains(string(stderr), "success\n\x1b[?25h")
}
