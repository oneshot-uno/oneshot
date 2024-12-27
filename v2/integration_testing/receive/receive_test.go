package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	itest "github.com/forestnode-io/oneshot/v2/integration_testing"
	"github.com/forestnode-io/oneshot/v2/pkg/configuration"
	"github.com/forestnode-io/oneshot/v2/pkg/output"
	"github.com/stretchr/testify/suite"
)

func TestBasicTestSuite(t *testing.T) {
	suite.Run(t, new(ts))
}

type ts struct {
	itest.TestSuite
}

func (suite *ts) Test_FROM_ANY_TO_StdoutTTY__StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_FROM_ANY_TO_StdoutTTY__StderrNONTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))
}

func (suite *ts) Test_FROM_ANY_TO_File__StdoutTTY_StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "./test.txt"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	fileContents, err := os.ReadFile(filepath.Join(oneshot.WorkingDir, "test.txt"))
	suite.Require().NoError(err)
	suite.Assert().Equal("SUCCESS", string(fileContents))

	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal(string(stdout), "")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Contains(string(stderr), "success\n\x1b[?25h")
}

func (suite *ts) Test_FROM_ANY_TO_StdoutTTY_DecodeBase64() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "--decode-b64"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	var (
		payload        = []byte("SUCCESS")
		encodedPayload = make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	)
	base64.StdEncoding.Encode(encodedPayload, payload)
	client := itest.RetryClient{}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader(encodedPayload))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))
}

func (suite *ts) Test_FROM_ANY_TO_File_DecodeBase64() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "./test.txt", "--decode-b64"}
	oneshot.Start()
	defer oneshot.Cleanup()

	var (
		payload        = []byte("SUCCESS")
		encodedPayload = make([]byte, base64.StdEncoding.EncodedLen(len(payload)))
	)
	base64.StdEncoding.Encode(encodedPayload, payload)
	client := itest.RetryClient{}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader(encodedPayload))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	fileContents, err := os.ReadFile(filepath.Join(oneshot.WorkingDir, "test.txt"))
	suite.Require().NoError(err)
	suite.Assert().Equal("SUCCESS", string(fileContents))
}

func (suite *ts) Test_FROM_ANY_TO_FILE__JSON() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "./test.txt", "--output", "json"}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s/?q=1", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()

	// expect no dynamic out, only static output on stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	var report output.Report
	err = json.Unmarshal(stdout, &report)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(report.Success)
	suite.Assert().Equal(0, len(report.Attempts))

	req := report.Success.Request
	suite.Require().Equal("POST", req.Method)
	suite.Require().Equal("HTTP/1.1", req.Protocol)
	suite.Require().Equal(map[string][]string{
		"Accept-Encoding": {"gzip"},
		"User-Agent":      {"Go-http-client/1.1"},
		"Content-Type":    {"text/plain"},
		"Content-Length":  {fmt.Sprintf("%d", len("SUCCESS"))},
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
	suite.Require().NotEmpty(file.Path)
	suite.Require().Equal("text/plain", file.MIME)
	suite.Require().Nil(file.Content)
	suite.Require().Empty(file.Name)

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_FROM_ANY_TO_Stdout__JSON() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "--output", "json"}
	oneshot.Start()
	defer oneshot.Cleanup()

	// ---

	client := itest.RetryClient{
		Suite: &suite.Suite,
	}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%s/?q=1", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()

	// expect no dynamic out, only static output on stdout
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	var report output.Report
	err = json.Unmarshal(stdout, &report)
	suite.Assert().NoError(err)
	suite.Assert().NotNil(report.Success)
	suite.Assert().Equal(0, len(report.Attempts))

	req := report.Success.Request
	suite.Require().Equal("POST", req.Method)
	suite.Require().Equal("HTTP/1.1", req.Protocol)
	suite.Require().Equal(map[string][]string{
		"Accept-Encoding": {"gzip"},
		"User-Agent":      {"Go-http-client/1.1"},
		"Content-Type":    {"text/plain"},
		"Content-Length":  {fmt.Sprintf("%d", len("SUCCESS"))},
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
	suite.Require().Empty(file.Path)
	suite.Require().Equal("text/plain", file.MIME)
	suite.Require().NotNil(file.Content)
	suite.Require().Empty(file.Name)

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on http://.*\n`, string(stderr))
}

func (suite *ts) Test_MultipleClients() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive", "./test.txt"}
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

			payload := []byte("SUCCESS")
			resp, _ := http.Post(fmt.Sprintf("http://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader(payload))
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
		} else {
			gones++
		}
	}
	suite.Assert().Equal(1, oks)
	suite.Assert().Equal(runtime.NumCPU()-2, gones)

	oneshot.Wait()
	fileContents, err := os.ReadFile(filepath.Join(oneshot.WorkingDir, "test.txt"))
	suite.Require().NoError(err)
	suite.Assert().Equal("SUCCESS", string(fileContents))

	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Contains(string(stdout), "")

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Contains(string(stderr), "success\n\x1b[?25h")
}

func (suite *ts) Test_TLS_FROM_ANY_TO_StdoutTTY__StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}
	caFilePath := filepath.Join(oneshot.TempDir, "ca.pem")
	oneshot.Configuration = &configuration.Root{
		Server: configuration.Server{
			TLS: &configuration.TLS{
				Certificate: &configuration.StaticOrGeneratedCertificate{
					GeneratedCertificate: &configuration.GeneratedCertificate{
						Subject: &configuration.PKIXName{
							CommonName: "localhost",
						},
						ExportCA: &configuration.FileExport{
							Path: caFilePath,
						},
					},
				},
			},
		},
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	suite.WaitForFileToExist(caFilePath, time.Second)
	rootCAFile, err := os.ReadFile(caFilePath)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(rootCAFile)

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(rootCAFile)
	suite.Require().True(ok)

	var certValidationError error

	client := itest.RetryClient{
		Suite: &suite.Suite,
		TLSConfig: &tls.Config{
			RootCAs: certPool,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				rootCert := verifiedChains[0][len(verifiedChains[0])-1]
				if rootCert.Subject.CommonName != "oneshot-local-ca" {
					certValidationError = errors.Join(certValidationError, fmt.Errorf("unexpected root cert subject: %+v", rootCert.Subject))
				}
				leafCert := verifiedChains[0][0]
				if leafCert.Subject.CommonName != "localhost" {
					certValidationError = errors.Join(certValidationError, fmt.Errorf("unexpected leaf cert subject: %+v", leafCert.Subject))
				}
				return nil
			},
		},
	}
	resp, err := client.Post(fmt.Sprintf("https://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on https://.*\n`, string(stderr))

	suite.Require().NoError(certValidationError)
}

func (suite *ts) Test_MTLS_FROM_ANY_TO_StdoutTTY__StderrTTY() {
	var oneshot = suite.NewOneshot()
	oneshot.Args = []string{"receive"}
	oneshot.Env = []string{
		"ONESHOT_TESTING_TTY_STDOUT=true",
		"ONESHOT_TESTING_TTY_STDERR=true",
	}

	clientCert, clientPKey := suite.GenerateSelfSignedCertAndKey(nil)

	caFilePath := filepath.Join(oneshot.TempDir, "ca.pem")
	oneshot.Configuration = &configuration.Root{
		Server: configuration.Server{
			TLS: &configuration.TLS{
				Certificate: &configuration.StaticOrGeneratedCertificate{
					GeneratedCertificate: &configuration.GeneratedCertificate{
						Subject: &configuration.PKIXName{
							CommonName: "localhost",
						},
						ExportCA: &configuration.FileExport{
							Path: caFilePath,
						},
					},
				},
				MTLS: &configuration.MTLS{
					Mode: configuration.MTLSModeRequire,
					CertPool: &configuration.CertPool{
						Certs: []configuration.PathOrContent{
							{
								Content: string(pem.EncodeToMemory(&pem.Block{
									Type:  "CERTIFICATE",
									Bytes: clientCert.Raw,
								})),
							},
						},
					},
				},
			},
		},
	}
	oneshot.Start()
	defer oneshot.Cleanup()

	suite.WaitForFileToExist(caFilePath, time.Second)
	rootCAFile, err := os.ReadFile(caFilePath)
	suite.Require().NoError(err)
	suite.Require().NotEmpty(rootCAFile)

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(rootCAFile)
	suite.Require().True(ok)

	client := itest.RetryClient{
		Suite: &suite.Suite,
		TLSConfig: &tls.Config{
			RootCAs: certPool,
			Certificates: []tls.Certificate{
				{
					Certificate: [][]byte{clientCert.Raw},
					PrivateKey:  clientPKey,
				},
			},
		},
	}
	resp, err := client.Post(fmt.Sprintf("https://127.0.0.1:%s", oneshot.Port), "text/plain", bytes.NewReader([]byte("SUCCESS")))
	suite.Require().NoError(err)
	suite.Require().NotNil(resp)
	suite.Assert().Equal(http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	oneshot.Wait()
	stdout := oneshot.Stdout.(*bytes.Buffer).Bytes()
	suite.Assert().Equal("SUCCESS", string(stdout))

	stderr := oneshot.Stderr.(*bytes.Buffer).Bytes()
	suite.Assert().Regexp(`listening on https://.*\n`, string(stderr))
}
