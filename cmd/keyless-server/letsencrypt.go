package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
)

var privateKeys = make(map[string]crypto.Signer)

const (
	letsencryptProduction = "https://acme-v02.api.letsencrypt.org/"
	letsencryptStaging    = "https://acme-staging-v02.api.letsencrypt.org/"
)

func loadCertificateAndKeys() error {
	cert, err := loadCertificate(config.Certificate, config.MasterKey, "*."+config.Domain)
	if err != nil {
		return err
	}

	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("unexpected type %T", cert.PrivateKey)
	}

	keys := []crypto.Signer{key}
	if config.LegacyKeys != "" {
		matches, err := filepath.Glob(config.LegacyKeys)
		if err != nil {
			return err
		}

		for _, match := range matches {
			key, err := loadKey(match)
			if err != nil {
				return err
			}
			keys = append(keys, key)
		}
	}

	for _, key := range keys {
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return err
		}

		hash := sha256.Sum256(der)
		privateKeys[base64.RawURLEncoding.EncodeToString(hash[:])] = key
	}
	return nil
}

func loadAPI() error {
	var hostname string
	if i := strings.IndexByte(config.API.Handler, '/'); i > 0 {
		hostname = config.API.Handler[:i]
	}
	_, err := loadCertificate(config.API.Certificate, config.API.Key, hostname)
	if err != nil {
		return err
	}

	if config.API.ClientCA != "" {
		cert, err := ioutil.ReadFile(config.API.ClientCA)
		if err != nil {
			return err
		}

		if pool := x509.NewCertPool(); !pool.AppendCertsFromPEM(cert) {
			return errors.New("could not parse client CA certificate")
		}
	}
	return nil
}

func loadAccount() (acct acme.Account, err error) {
	acct.PrivateKey, err = loadKey(config.LetsEncrypt.AccountKey)
	if err != nil {
		return acct, err
	}

	f, err := os.Open(config.LetsEncrypt.Account)
	if err != nil {
		return acct, err
	}

	defer f.Close()
	return acct, json.NewDecoder(f).Decode(&acct)
}

func loadKey(keyFile string) (*ecdsa.PrivateKey, error) {
	buf, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}

	blk, _ := pem.Decode(buf)
	if blk == nil {
		return nil, errors.New("no PEM data found")
	}

	return x509.ParseECPrivateKey(blk.Bytes)
}

func loadCertificate(certFile, keyFile, hostname string) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := verifyCertificate(cert, hostname); err != nil {
		return tls.Certificate{}, err
	}
	return cert, nil
}

func verifyCertificate(cert tls.Certificate, hostname string) (err error) {
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if now := time.Now(); now.Before(cert.Leaf.NotBefore) || now.After(cert.Leaf.NotAfter) {
		return errors.New("expired certificate")
	}
	if hostname != "" {
		return cert.Leaf.VerifyHostname(hostname)
	}
	return nil
}

func obtainCertificate(ctx context.Context, client *acmez.Client, acct acme.Account, key crypto.Signer, certFile string, domains ...string) error {
	certs, err := client.ObtainCertificate(ctx, acct, key, domains)
	if err != nil {
		return err
	}

	for _, acme := range certs {
		f, err := ioutil.TempFile(filepath.Split(certFile))
		if err != nil {
			return err
		}
		_, err = f.Write(acme.ChainPEM)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		return os.Rename(f.Name(), certFile)
	}
	return errors.New("no certificates obtained")
}

var (
	solvers acmeSolvers
	_       acmez.Solver = &solvers
)

type acmeSolvers struct {
	sync.Mutex
	challanges []acmeChallenge
}

type acmeChallenge struct {
	Created time.Time
	acme.Challenge
}

func (c acmeChallenge) Expired() bool {
	return time.Since(c.Created) > time.Minute
}

func (s *acmeSolvers) RemoveChallenges(match func(c acmeChallenge) bool) {
	var n int
	for _, c := range s.challanges {
		if !match(c) {
			s.challanges[n] = c
			n++
		}
	}
	for i := range s.challanges[n:] {
		s.challanges[i] = acmeChallenge{}
	}
	s.challanges = s.challanges[:n]
}

func (s *acmeSolvers) GetDNSChallenges(domain string) []string {
	s.Lock()
	defer s.Unlock()
	s.RemoveChallenges(acmeChallenge.Expired)

	var res []string
	for _, c := range s.challanges {
		if c.Type == acme.ChallengeTypeDNS01 &&
			strings.EqualFold(c.Identifier.Value, domain) {
			res = append(res, c.DNS01KeyAuthorization())
		}
	}
	return res
}

func (s *acmeSolvers) GetTLSChallengeCert(serverName string) (*tls.Certificate, error) {
	s.Lock()
	defer s.Unlock()
	s.RemoveChallenges(acmeChallenge.Expired)

	for _, c := range s.challanges {
		if c.Type == acme.ChallengeTypeTLSALPN01 &&
			strings.EqualFold(c.Identifier.Value, serverName) {
			return acmez.TLSALPN01ChallengeCert(c.Challenge)
		}
	}
	return nil, errors.New("no matching challanges found")
}

func (s *acmeSolvers) HandleHTTPChallenge(w http.ResponseWriter, r *http.Request) {
	s.Lock()
	defer s.Unlock()
	s.RemoveChallenges(acmeChallenge.Expired)

	for _, c := range s.challanges {
		if c.Type == acme.ChallengeTypeHTTP01 &&
			r.Method == "GET" &&
			r.URL.Path == c.HTTP01ResourcePath() &&
			strings.EqualFold(c.Identifier.Value, r.Host) {
			w.Write([]byte(c.KeyAuthorization))
			r.Close = true
		}
	}
}

func (s *acmeSolvers) GetDNSSolvers() map[string]acmez.Solver {
	return map[string]acmez.Solver{
		acme.ChallengeTypeDNS01: &solvers,
	}
}

func (s *acmeSolvers) GetAPISolvers() map[string]acmez.Solver {
	return map[string]acmez.Solver{
		acme.ChallengeTypeHTTP01:    &solvers,
		acme.ChallengeTypeTLSALPN01: &solvers,
	}
}

func (s *acmeSolvers) Present(_ context.Context, chal acme.Challenge) error {
	s.Lock()
	defer s.Unlock()
	s.RemoveChallenges(acmeChallenge.Expired)

	s.challanges = append(s.challanges, acmeChallenge{
		Created:   time.Now(),
		Challenge: chal,
	})
	return nil
}

func (s *acmeSolvers) CleanUp(_ context.Context, chal acme.Challenge) error {
	s.Lock()
	defer s.Unlock()
	s.RemoveChallenges(func(c acmeChallenge) bool { return chal == c.Challenge })
	return nil
}
