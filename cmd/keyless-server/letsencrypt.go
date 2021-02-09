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

func obtainCertificate(ctx context.Context, client *acmez.Client, acct acme.Account, key crypto.Signer, domain string) error {
	certs, err := client.ObtainCertificate(ctx, acct, key, []string{domain})
	if err != nil {
		return err
	}

	for _, acme := range certs {
		return ioutil.WriteFile(config.Certificate, acme.ChainPEM, 0400)
	}
	return errors.New("no certificates obtained")
}

var dnsSolver dns01Solver

type dns01Solver struct {
	sync.Mutex
	challange string
	timestamp time.Time
}

func (s *dns01Solver) getChallenges() []string {
	s.Lock()
	defer s.Unlock()
	if s.challange != "" {
		return []string{s.challange}
	}
	return nil
}

func (s *dns01Solver) Present(_ context.Context, chal acme.Challenge) error {
	if chal.Type != acme.ChallengeTypeDNS01 {
		return errors.New("unexpected challenge")
	}

	s.Lock()
	defer s.Unlock()
	if s.challange != "" {
		return errors.New("already running a challenge")
	}
	s.challange = chal.DNS01KeyAuthorization()
	return nil
}

func (s *dns01Solver) CleanUp(context.Context, acme.Challenge) error {
	s.Lock()
	defer s.Unlock()
	s.challange = ""
	return nil
}
