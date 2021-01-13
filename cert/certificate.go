// Copyright 2018 ouqiang authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

// Package cert 证书管理
package cert

import (
	crand "crypto/rand"
	"math/rand"
	"strings"

	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

var (
	defaultRootCAPem = []byte(`
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIQUZOslcv7HVi+6AC+YFkUkTANBgkqhkiG9w0BAQsFADAo
MRIwEAYDVQQKEwlsb2NhbGhvc3QxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0yMTAx
MTIwMzM2MjhaFw0zMTAxMTAwMzM2MjhaMCgxEjAQBgNVBAoTCWxvY2FsaG9zdDES
MBAGA1UEAxMJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAmU1rOI/yPAowny5cqnPys0oQK5JJ5QMJghCoPbfaAa/DbADpCfmr/PHq/N7d
dKk19oF8GppvKSQJux+2VMrrJpCZuFAYbbBwG958VySR4vWZ0qh2NdhXhLk/XP+w
EP/CCrLpRlHqsNQ8vs2eKDpfBmLmgqwgV0FfFpRKiP2AhZKo/Ac8n1UROxIVGXTY
FTfUCJMsw67RUSX9Cnawy2+zUzN2u4h3tpauPCav4Gp3kn8ticd0Uj6Z8rToFy+i
s6/BNvSsePJgGZra7X8+bw4R/NI34/EF83sEV/oLBX6PZOF9m0WqmsWnnWtamuYg
xut/N7rryNEzf3kOO54PLTghowIDAQABozUwMzAOBgNVHQ8BAf8EBAMCBaAwEwYD
VR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOC
AQEADDcvJKsWjIsIZCW8hY83/GRK1RyDsVk4pdCsqNzXeKMpgNEgxvbjeFDGb4Eb
bgciqUqedfi8A/zSylTQnpIDAWbPXZ2r0jVU1NKFI+todwWJerO4puAHXuoMYE4V
GYxb6ktQis7amDd29hpxnmnl/KUqrXatkTlU/h1iSfLNi9OR6dpJnJbUU23sV+xL
KLsIUuaIbuj/+NKvQqz1bdOkVaZuQQnFStwBZWROQBoz1P9dxlOaBQBWBseLEAyK
+4/EmquUnmZXvhIl6psJD81IjX4cyPqUlQNMJ7HTUR0PdsIKLvfrCypoR5jdXbna
/RvosYzCqiKg8oM0h910G8WbLw==
-----END CERTIFICATE-----	
`)
	defaultRootKeyPem = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAmU1rOI/yPAowny5cqnPys0oQK5JJ5QMJghCoPbfaAa/DbADp
Cfmr/PHq/N7ddKk19oF8GppvKSQJux+2VMrrJpCZuFAYbbBwG958VySR4vWZ0qh2
NdhXhLk/XP+wEP/CCrLpRlHqsNQ8vs2eKDpfBmLmgqwgV0FfFpRKiP2AhZKo/Ac8
n1UROxIVGXTYFTfUCJMsw67RUSX9Cnawy2+zUzN2u4h3tpauPCav4Gp3kn8ticd0
Uj6Z8rToFy+is6/BNvSsePJgGZra7X8+bw4R/NI34/EF83sEV/oLBX6PZOF9m0Wq
msWnnWtamuYgxut/N7rryNEzf3kOO54PLTghowIDAQABAoIBAB4yRrVsfS1gYHVq
X2xfzGWOaCL8/Ls0XvIUr98AUNvWMCsc/sotOLhpOn02tO5eyjdVCAoBc3XqGFSY
iYSoN6tv/id092rbvyluKJXNqULIV9VLw4UVqR+GkbmSz655glIzLYnhZtYP6Cs5
Ozb3UHJklr0UhIZLZRyAdzIGpQMqMz2++JRrCbKFX+m3f2t3oTyztFzUjeChpjdf
G+k9aRsdTVkfRGwp7VZ0YDjM+MmF5xOOzPrd7KOdzlT1CMDE9r0tjmhhiFF3PZLY
U9q1X0ruxhcEpHaasFzCjfXSV4QjZjmRS5rF5UAlq4VCPLeJSrulAXKMuAmCywzI
VEr4CxECgYEAxqScGqquh5cYSeaYQr6vvpHOe9RXwEBtAagzrHHUJMlDUMj9el+A
f7QqtxidaKeyJ4WsQMDa3ZqAi0gGQo1164ie8PJN0nyS94HFiENkozx2aWNcDKsv
EZNl0seqj5tdKXJL7mV2SnKS/kbQU1BOfMrLcdcGZm+4zPvo0aTozssCgYEAxZFN
JDqA2zHix/HOsugrnf6h7QhPI9d6wUImE+kZawfbjeniZPgWr/swXz6Q1t1XePfL
JwBn+DQ42GvcI5vZlYtY0IdCPIYidhcRfXj/rZwqXgEh8ZVCHNxHYS9xzv46zryl
yV/v4GiuIH/WYhUQV4q/L4wD+3tMbhNbqWNWhYkCgYB6FfuXbCWeUh/sc5xLEVWE
Q6rrcmOIVlBov08bAk7HWSdVRGJ9zqp0UnAaXjeIdeDJ558poR4jKu0sLVUjnDvI
Sgydu95WqpfNJOYZzInSxbtlJFsTsjZYkAX52Rub7XoBmizO1W8xbF+phi5NtkK2
8hC949EcLjgfTAgYqUkopwKBgD7F3wPOzthWbl7nFqzDlfA6Uoq0pCiYM3mqId0b
qCbYtUrO8E7ygIrjvcfVYkHSzBM0cEjxGRfEx/cDtkteHnEkeFCxWTtPxy1MQRNj
2aD4yIFbzMQsj3gKCWf4oimJn3fGesqT/+yGdiT/WUeKt8mI3RwnWbCSyYMEBZC5
bmk5AoGAWTBpuAO/Z+9jXCCECLw1JrMGAVpF+S9abHOnXwZ10e15SgJ4HbZJ37qr
E9SdJgb9CfS8Res99qHa2Y6Fj47jUxahuFh/5WbsdzGcDnqCb1ND0Z8Z2ic8zBu4
F2XjYq9REkOWy9yqfnmCpEC5RvdBrih/QgqbwPVwVABsWaPKeyY=
-----END RSA PRIVATE KEY-----
`)
)

var (
	defaultRootCA  *x509.Certificate
	defaultRootKey *rsa.PrivateKey
)

func init() {
	var err error
	block, _ := pem.Decode(defaultRootCAPem)
	defaultRootCA, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("加载根证书失败: %s", err))
	}
	block, _ = pem.Decode(defaultRootKeyPem)
	defaultRootKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("加载根证书私钥失败: %s", err))
	}
}

// Certificate 证书管理
type Certificate struct {
	cache Cache
}

type Pair struct {
	Cert            *x509.Certificate
	CertBytes       []byte
	PrivateKey      *rsa.PrivateKey
	PrivateKeyBytes []byte
}

func NewCertificate(cache Cache) *Certificate {
	return &Certificate{
		cache: cache,
	}
}

// GenerateTlsConfig 生成TLS配置
func (c *Certificate) GenerateTlsConfig(host string) (*tls.Config, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if c.cache != nil {
		// 先从缓存中查找证书
		if cert := c.cache.Get(host); cert != nil {
			tlsConf := &tls.Config{
				Certificates: []tls.Certificate{*cert},
			}

			return tlsConf, nil
		}
	}
	pair, err := c.GeneratePem(host, 1, defaultRootCA, defaultRootKey)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(pair.CertBytes, pair.PrivateKeyBytes)
	if err != nil {
		return nil, err
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if c.cache != nil {
		// 缓存证书
		c.cache.Set(host, &cert)
	}

	return tlsConf, nil
}

// Generate 生成证书
func (c *Certificate) GeneratePem(host string, expireDays int, rootCA *x509.Certificate, rootKey *rsa.PrivateKey) (*Pair, error) {
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := c.template(host, expireDays)
	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, rootCA, &priv.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	serverCert := pem.EncodeToMemory(certBlock)

	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	serverKey := pem.EncodeToMemory(keyBlock)

	p := &Pair{
		Cert:            tmpl,
		CertBytes:       serverCert,
		PrivateKey:      priv,
		PrivateKeyBytes: serverKey,
	}

	return p, nil
}

// GenerateCA 生成根证书
func (c *Certificate) GenerateCA() (*Pair, error) {
	priv, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(rand.Int63()),
		Subject: pkix.Name{
			CommonName:   "Mars",
			Country:      []string{"China"},
			Organization: []string{"4399.com"},
			Province:     []string{"FuJian"},
			Locality:     []string{"Xiamen"},
		},
		NotBefore:             time.Now().AddDate(0, -1, 0),
		NotAfter:              time.Now().AddDate(30, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		EmailAddresses:        []string{"qingqianludao@gmail.com"},
	}

	derBytes, err := x509.CreateCertificate(crand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	}
	serverCert := pem.EncodeToMemory(certBlock)

	keyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}
	serverKey := pem.EncodeToMemory(keyBlock)

	p := &Pair{
		Cert:            tmpl,
		CertBytes:       serverCert,
		PrivateKey:      priv,
		PrivateKeyBytes: serverKey,
	}

	return p, nil
}

func (c *Certificate) template(host string, expireYears int) *x509.Certificate {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(expireYears, 0, 0),
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		EmailAddresses:        []string{"qingqianludao@gmail.com"},
	}
	hosts := strings.Split(host, ",")
	for _, item := range hosts {
		if ip := net.ParseIP(host); ip != nil {
			cert.IPAddresses = append(cert.IPAddresses, ip)
		} else {
			cert.DNSNames = append(cert.DNSNames, item)
		}
	}

	return cert
}

// RootCA 根证书
func DefaultRootCAPem() []byte {
	return defaultRootCAPem
}
