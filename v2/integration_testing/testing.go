package itest

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/ssl"
	"github.com/stretchr/testify/suite"
)

var MiscPortPool = &PortPool{start: 5000, end: 6000}

type FilesMap map[string][]byte

func (fm FilesMap) ProjectInto(dir string) error {
	for path, contents := range fm {
		var (
			path      = filepath.Join(dir, path)
			parentDir = filepath.Dir(path)
		)
		if err := os.MkdirAll(parentDir, 0700); err != nil {
			return err
		}

		if err := os.WriteFile(path, contents, os.ModePerm); err != nil {
			return err
		}
	}

	return nil
}

func EOFReader(data []byte) io.Reader {
	return &stdinPayload{data: data}
}

type stdinPayload struct {
	data []byte

	r *io.PipeReader
	w *io.PipeWriter
}

func (sp *stdinPayload) Read(p []byte) (int, error) {
	if sp.r == nil || sp.w == nil {
		sp.r, sp.w = io.Pipe()
		go func() {
			sp.w.Write(sp.data)
			sp.w.Close()
		}()
	}

	return sp.r.Read(p)
}

type RetryClient struct {
	client    http.RoundTripper
	Suite     *suite.Suite
	TLSConfig *tls.Config
}

func (rc *RetryClient) Post(url, mime string, body io.Reader) (*http.Response, error) {
	var response *http.Response

	if rc.client == nil {
		rc.client = &http.Transport{
			TLSClientConfig: rc.TLSConfig,
		}
	}

	for response == nil {
		req, err := http.NewRequest("POST", url, body)
		if err != nil {
			panic(fmt.Sprintf("invalid url: %v", err))
		}
		req.Header.Set("Content-Type", mime)
		response, err = rc.client.RoundTrip(req)
		if err != nil {
			if !strings.Contains(err.Error(), "refused") {
				return nil, err
			}
		}
	}

	return response, nil
}

func (rc *RetryClient) Get(url string) (*http.Response, error) {
	var response *http.Response

	if rc.client == nil {
		rc.client = &http.Transport{}
	}

	for response == nil {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		response, err = rc.client.RoundTrip(req)
		if err != nil {
			if !strings.Contains(err.Error(), "refused") {
				return nil, err
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return response, nil
}

func (rc *RetryClient) Do(req *http.Request) (*http.Response, error) {
	var response *http.Response

	if rc.client == nil {
		rc.client = &http.Transport{}
	}

	for response == nil {
		var err error
		response, err = rc.client.RoundTrip(req)
		if err != nil {
			if !strings.Contains(err.Error(), "refused") {
				return nil, err
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return response, nil
}

type TestSuite struct {
	suite.Suite
	TestDir string
}

func (suite *TestSuite) SetupSuite() {
	tempDir, err := os.MkdirTemp("", "")
	suite.Require().NoError(err)
	suite.TestDir = tempDir

	cmdPath, err := filepath.EvalSymlinks("../../build-output/oneshot")
	suite.Require().NoError(err)

	newCmdPath := filepath.Join(suite.TestDir, "oneshot.testing")
	if runtime.GOOS == "darwin" {
		newCmdPath = filepath.Join(filepath.Dir(suite.TestDir), "oneshot.testing")
	}
	cpOut, err := exec.Command("cp", cmdPath, newCmdPath).CombinedOutput()
	suite.Require().NoError(err, "failed to copy oneshot binary: %s", string(cpOut))

	err = os.Chdir(suite.TestDir)
	suite.Require().NoError(err)
}

func (suite *TestSuite) TearDownSuite() {
	err := os.RemoveAll(suite.TestDir)
	suite.Require().NoError(err)
}

func (suite *TestSuite) NewOneshot() *Oneshot {
	wdir, err := os.MkdirTemp(suite.TestDir, "subtest-working-dir*")
	suite.Require().NoError(err)
	tdir, err := os.MkdirTemp(suite.TestDir, "subtest-temp-dir*")
	suite.Require().NoError(err)
	return &Oneshot{
		T:          suite.T(),
		WorkingDir: wdir,
		TempDir:    tdir,
		Port:       oneshotPortPool.Get(),
	}
}

func (suite *TestSuite) WaitForFileToExist(path string, timeout time.Duration) {
	start := time.Now()
	for time.Since(start) < timeout {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	suite.Failf("file was not created", "file %s was not created within %s", path, timeout)
}

func (suite *TestSuite) GenerateSelfSignedCertAndKey(config *configuration.GeneratedCertificate) (*x509.Certificate, any) {
	conf := config
	if conf == nil {
		conf = &configuration.GeneratedCertificate{
			Subject: &configuration.PKIXName{
				CommonName: "localhost",
			},
		}
	}

	privKey, pubKey, err := ssl.GeneratePrivateKey(conf.GetPrivateKeyAlgorithm())
	suite.Require().NoError(err)

	certTemplate, err := ssl.CertFromConfig(conf, true)
	suite.Require().NoError(err)
	certTemplate.IsCA = true
	certTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	certTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	certBytes, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, pubKey, privKey)
	suite.Require().NoError(err)

	cert, err := x509.ParseCertificate(certBytes)
	suite.Require().NoError(err)

	return cert, privKey
}
