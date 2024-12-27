package ssl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/forestnode-io/oneshot/v2/pkg/configuration"
)

func GetTLSConfig(config *configuration.TLS) (*tls.Config, error) {
	if !config.IsEnabled() {
		return nil, nil
	}

	var (
		tc  tls.Config
		err error
	)

	// If we are using mTLS, we dont need a cert pol unless we are verifying the client
	// presented certificate.
	// We also have the option to use the system cert pool.
	if config.MTLS != nil {
		var certPool *x509.CertPool
		if config.MTLS.CertPool != nil {
			if config.MTLS.CertPool.UseSystemRoots {
				certPool, err = x509.SystemCertPool()
				if err != nil {
					return nil, fmt.Errorf("failed to get system cert pool for mTLS: %w", err)
				}
			}
			if config.MTLS.CertPool.Certs != nil {
				if certPool == nil {
					certPool = x509.NewCertPool()
				}
				for _, certPathOrContent := range config.MTLS.CertPool.Certs {
					certBytes, err := certPathOrContent.GetContent()
					if err != nil {
						return nil, fmt.Errorf("failed to get cert: %w", err)
					}
					ok := certPool.AppendCertsFromPEM(certBytes)
					if !ok {
						return nil, fmt.Errorf("failed to append cert to pool")
					}
				}
			}
		}
		if certPool != nil {
			tc.ClientCAs = certPool
			switch config.MTLS.Mode {
			case configuration.MTLSModeRequire:
				tc.ClientAuth = tls.RequireAndVerifyClientCert
			case configuration.MTLSModeRequest:
				tc.ClientAuth = tls.VerifyClientCertIfGiven
			}
		} else {
			switch config.MTLS.Mode {
			case configuration.MTLSModeRequire:
				tc.ClientAuth = tls.RequireAnyClientCert
			case configuration.MTLSModeRequest:
				tc.ClientAuth = tls.RequestClientCert
			}
		}
	}

	// If we are using static certificates, we need to load the certificate and key
	// and set the cert in the tls.Config.
	if config.Certificate.Certificate != nil {
		cert, err := config.Certificate.Certificate.GetContent()
		if err != nil {
			return nil, err
		}

		key, err := config.PrivateKey.GetContent()
		if err != nil {
			return nil, err
		}

		x509KP, err := tls.X509KeyPair(cert, key)
		if err != nil {
			return nil, fmt.Errorf("failed to get x509 key pair: %w", err)
		}

		tc.Certificates = []tls.Certificate{x509KP}
	} else if config.Certificate.GeneratedCertificate.GenerateAtStartup {
		rootCert, rootPrivKey, err := generateRootCertAndKey(config.Certificate.GeneratedCertificate)
		if err != nil {
			return nil, err
		}

		leafCert, leafKey, err := generateLeafCertAndKey(config.Certificate.GeneratedCertificate, rootCert, rootPrivKey, nil)
		if err != nil {
			return nil, err
		}

		x509KP, err := tls.X509KeyPair(leafCert, leafKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get x509 key pair: %w", err)
		}

		tc.Certificates = []tls.Certificate{x509KP}
	} else {
		rootCert, rootPrivKey, err := generateRootCertAndKey(config.Certificate.GeneratedCertificate)
		if err != nil {
			return nil, err
		}

		tc.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			leafCert, leafKey, err := generateLeafCertAndKey(config.Certificate.GeneratedCertificate, rootCert, rootPrivKey, hello)
			if err != nil {
				return nil, err
			}

			x509KP, err := tls.X509KeyPair(leafCert, leafKey)
			if err != nil {
				return nil, fmt.Errorf("failed to get x509 key pair: %w", err)
			}

			return &x509KP, nil
		}
	}

	return &tc, nil
}

func generateRootCertAndKey(config *configuration.GeneratedCertificate) (*x509.Certificate, any, error) {
	pkeyAlgorithm := config.GetPrivateKeyAlgorithm()

	rootPrivKey, rootPubKey, err := GeneratePrivateKey(pkeyAlgorithm)
	if err != nil {
		return nil, nil, err
	}
	rootCertTemplate, err := CertFromConfig(config, false)
	if err != nil {
		return nil, nil, err
	}
	rootCertTemplate.IsCA = true
	rootCertTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootCertTemplate, rootCertTemplate, rootPubKey, rootPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	if config.ExportCA != nil {
		if config.ExportCA.Path != "" {
			mode := os.FileMode(0644)
			if config.ExportCA.Mode != "" {
				modeUint, err := strconv.ParseUint(config.ExportCA.Mode, 8, 32)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse mode: %w", err)
				}
				mode = os.FileMode(modeUint)
			}
			os.WriteFile(config.ExportCA.Path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootCertBytes}), mode)
		}
	}

	return rootCert, rootPrivKey, nil
}

func generateLeafCertAndKey(config *configuration.GeneratedCertificate, rootCert *x509.Certificate, rootPrivKey any, hello *tls.ClientHelloInfo) ([]byte, []byte, error) {
	pkeyAlgorithm := config.GetPrivateKeyAlgorithm()

	leafPrivKey, leafPubKey, err := GeneratePrivateKey(pkeyAlgorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	leafCertTemplate, err := CertFromConfig(config, true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate template: %w", err)
	}
	leafCertTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	leafCertTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}

	if hello != nil {
		leafCertTemplate.DNSNames = append(leafCertTemplate.DNSNames, hello.ServerName)
		localAddr := hello.Conn.LocalAddr().String()
		localHost, _, err := net.SplitHostPort(localAddr)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to split local address: %w", err)
		}
		leafCertTemplate.IPAddresses = append(leafCertTemplate.IPAddresses, net.ParseIP(localHost))
	}

	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafCertTemplate, rootCert, leafPubKey, rootPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCertBytes})
	leafKeyBytes, err := x509.MarshalPKCS8PrivateKey(leafPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	var leafKeyBlockType string
	switch pkeyAlgorithm {
	case "rsa-2048", "rsa-3072", "rsa-7680":
		leafKeyBlockType = "RSA PRIVATE KEY"
	case "ecdsa-p224", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		leafKeyBlockType = "EC PRIVATE KEY"
	}

	leafKeyPEM := pem.EncodeToMemory(&pem.Block{Type: leafKeyBlockType, Bytes: leafKeyBytes})

	return leafCertPEM, leafKeyPEM, nil
}

func GeneratePrivateKey(algorithm string) (any, any, error) {
	switch algorithm {
	case "rsa-2048":
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA-2048 private key: %w", err)
		}
		return privKey, privKey.PublicKey, nil
	case "rsa-3072":
		privKey, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA-3072 private key: %w", err)
		}
		return privKey, privKey.PublicKey, nil
	case "rsa-7680":
		privKey, err := rsa.GenerateKey(rand.Reader, 7680)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA-7680 private key: %w", err)
		}
		return privKey, privKey.PublicKey, nil
	case "ecdsa-p224":
		privKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA-P224 private key: %w", err)
		}
		return privKey, privKey.Public(), nil
	case "ecdsa-p256":
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA-P256 private key: %w", err)
		}
		return privKey, privKey.Public(), nil
	case "ecdsa-p384":
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA-P384 private key: %w", err)
		}
		return privKey, privKey.Public(), nil
	case "ecdsa-p521":
		privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA-P521 private key: %w", err)
		}
		return privKey, privKey.Public(), nil
	}
	return nil, nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
}

func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

func CertFromConfig(config *configuration.GeneratedCertificate, isLeaf bool) (*x509.Certificate, error) {
	var (
		pkeyAlgorithm = config.GetPrivateKeyAlgorithm()
		cert          = x509.Certificate{
			NotBefore:             time.Now(),
			NotAfter:              time.Now().AddDate(1, 0, 0),
			BasicConstraintsValid: true,
		}
		err error
	)

	cert.SerialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	switch pkeyAlgorithm {
	case "rsa-2048", "rsa-3072", "rsa-7680":
		cert.SignatureAlgorithm = x509.SHA256WithRSA
	case "ecdsa-p224", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		cert.SignatureAlgorithm = x509.ECDSAWithSHA256
	}

	if config.Subject != nil {
		cert.Subject = config.Subject.ToStdLib()
	}

	if config.Subject.CommonName == "" {
		cert.Subject.CommonName = "oneshot"
		if !isLeaf {
			cert.Subject.CommonName += "-local-ca"
		}
	}

	if config.NotBefore != "" {
		cert.NotBefore, err = parseTime(config.NotBefore)
		if err != nil {
			return nil, fmt.Errorf("failed to parse notBefore: %w", err)
		}
	} else {
		cert.NotBefore = time.Now()
	}

	if config.NotAfter != "" {
		cert.NotAfter, err = parseTime(config.NotAfter)
		if err != nil {
			return nil, fmt.Errorf("failed to parse notAfter: %w", err)
		}
	} else {
		cert.NotAfter = cert.NotBefore.AddDate(1, 0, 0)
	}

	return &cert, nil
}
