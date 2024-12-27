package configuration

import (
	"crypto/x509/pkix"
	"errors"
)

type PKIXName struct {
	CommonName         string                   `mapstructure:"commonName" yaml:"commonName"`
	Country            SingletonOrSlice[string] `mapstructure:"country" yaml:"country"`
	Organization       SingletonOrSlice[string] `mapstructure:"organization" yaml:"organization"`
	OrganizationalUnit SingletonOrSlice[string] `mapstructure:"organizationalUnit" yaml:"organizationalUnit"`
	Locality           SingletonOrSlice[string] `mapstructure:"locality" yaml:"locality"`
	Province           SingletonOrSlice[string] `mapstructure:"province" yaml:"province"`
	StreetAddress      SingletonOrSlice[string] `mapstructure:"streetAddress" yaml:"streetAddress"`
	PostalCode         SingletonOrSlice[string] `mapstructure:"postalCode" yaml:"postalCode"`
}

func (pn PKIXName) ToStdLib() pkix.Name {
	return pkix.Name{
		CommonName:         pn.CommonName,
		Country:            pn.Country,
		Organization:       pn.Organization,
		OrganizationalUnit: pn.OrganizationalUnit,
		Locality:           pn.Locality,
		Province:           pn.Province,
		StreetAddress:      pn.StreetAddress,
		PostalCode:         pn.PostalCode,
	}
}

type GeneratedCertificate struct {
	Subject                 *PKIXName   `mapstructure:"subject" yaml:"subject"`
	NotBefore               string      `mapstructure:"notBefore" yaml:"notBefore"`
	NotAfter                string      `mapstructure:"notAfter" yaml:"notAfter"`
	SubjectAlternativeNames []string    `mapstructure:"subjectAlternativeNames" yaml:"subjectAlternativeNames"`
	PrivateKeyAlgorithm     string      `mapstructure:"privateKeyAlgorithm" yaml:"privateKeyAlgorithm"`
	ExportCA                *FileExport `mapstructure:"exportCA" yaml:"exportCA"`
	GenerateAtStartup       bool        `mapstructure:"generateAtStartup" yaml:"generateAtStartup"`
}

const defaultPrivatyeKeyAlgorithm = "ecdsa-p384"

func (gc GeneratedCertificate) GetPrivateKeyAlgorithm() string {
	if gc.PrivateKeyAlgorithm == "" {
		return defaultPrivatyeKeyAlgorithm
	}
	return gc.PrivateKeyAlgorithm
}

type StaticOrGeneratedCertificate struct {
	Certificate          *PathOrContent        `mapstructure:"certificate" yaml:"certificate"`
	GeneratedCertificate *GeneratedCertificate `mapstructure:"generatedCertificate" yaml:"generatedCertificate"`
}

func (sogc *StaticOrGeneratedCertificate) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if sogc == nil {
		*sogc = StaticOrGeneratedCertificate{}
	}

	type sogc_t StaticOrGeneratedCertificate
	if err := unmarshal((*sogc_t)(sogc)); err != nil {
		return err
	}

	if sogc.Certificate != nil && sogc.GeneratedCertificate != nil {
		return errors.New("only one of certificate or generatedCertificate can be specified")
	}

	return nil
}

type MTLSMode string

const (
	MTLSModeDisabled MTLSMode = "disabled"
	MTLSModeRequest  MTLSMode = "request"
	MTLSModeRequire  MTLSMode = "require"
)

type CertPool struct {
	UseSystemRoots bool            `mapstructure:"useSystemRoots" yaml:"useSystemRoots"`
	Certs          []PathOrContent `mapstructure:"certs" yaml:"certs"`
}

type MTLS struct {
	Mode     MTLSMode  `mapstructure:"mode" yaml:"mode"`
	CertPool *CertPool `mapstructure:"certPool" yaml:"certPool"`
}

type TLS struct {
	Certificate *StaticOrGeneratedCertificate `mapstructure:"certificate" yaml:"certificate"`
	PrivateKey  *PathOrContent                `mapstructure:"privateKey" yaml:"privateKey"`
	MTLS        *MTLS                         `mapstructure:"mtls" yaml:"mtls"`
}

func (t *TLS) IsEnabled() bool {
	if t == nil {
		return false
	}
	return t.Certificate != nil && (t.Certificate.Certificate != nil || t.Certificate.GeneratedCertificate != nil)
}

func (t *TLS) UnmarshalYAML(unmarshal func(interface{}) error) error {
	if t == nil {
		*t = TLS{}
	}

	type t_t TLS
	if err := unmarshal((*t_t)(t)); err != nil {
		return err
	}

	if t.MTLS == nil && t.Certificate == nil && t.PrivateKey == nil {
		return nil
	}

	if (t.MTLS != nil && t.MTLS.Mode != MTLSModeDisabled) && t.Certificate == nil {
		return errors.New("mTLS cannot be used without a server certificate")
	}

	if t.Certificate.Certificate != nil && t.Certificate.GeneratedCertificate != nil {
		return errors.New("only one of certificate or generatedCertificate can be specified")
	}

	if t.Certificate.Certificate != nil && t.PrivateKey == nil {
		return errors.New("private key must be specified when using a static certificate")
	}

	if t.Certificate.GeneratedCertificate != nil && t.PrivateKey != nil {
		return errors.New("private key cannot be specified when using a generated certificate")
	}

	if t.Certificate.Certificate != nil && t.Certificate.GeneratedCertificate != nil {
		return errors.New("only one of certificate or generatedCertificate can be specified")
	}

	return nil
}
