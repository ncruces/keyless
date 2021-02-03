package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/mholt/acmez"
	"github.com/mholt/acmez/acme"
	"github.com/ncruces/go-cloudflare/acmecf"
)

var privateKeys = make(map[string]crypto.Signer)

func loadCertificate() error {
	cert, err := tls.LoadX509KeyPair(config.Certificate, config.MasterKey)
	if err != nil {
		return err
	}

	key, ok := cert.PrivateKey.(crypto.Signer)
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
			buf, err := ioutil.ReadFile(match)
			if err != nil {
				return err
			}

			blk, _ := pem.Decode(buf)
			if blk == nil {
				return errors.New("no PEM data found")
			}

			key, err := x509.ParseECPrivateKey(blk.Bytes)
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

func renewCertificate() {
	ctx := context.Background()

	solver, err := acmecf.NewDNS01Solver(config.Cloudflare.Zone, config.Cloudflare.Token)
	if err != nil {
		log.Fatalf("creating DNS01 solver: %v", err)
	}

	le := &acmez.Client{
		Client: &acme.Client{Directory: config.LetsEncrypt.API},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDNS01: solver,
		},
	}

	acct, err := createAccount(ctx, le)
	if err != nil {
		log.Fatalf("creating account: %v", err)
	}

	master, err := createKey(config.MasterKey)
	if err != nil {
		log.Fatalf("creating master key: %v", err)
	}

	err = createCertificate(ctx, le, acct, master, config.Domain)
	if err != nil {
		log.Fatalf("creating certificate: %v", err)
	}
}

func createKey(keyFile string) (*ecdsa.PrivateKey, error) {
	if buf, err := ioutil.ReadFile(keyFile); os.IsNotExist(err) {
		// generate new key
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}

		pem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		err = ioutil.WriteFile(keyFile, pem, 0600)
		if err != nil {
			return nil, err
		}

		return key, nil

	} else if err == nil {
		// load existing key
		blk, _ := pem.Decode(buf)
		if blk == nil {
			return nil, errors.New("no PEM data found")
		}
		return x509.ParseECPrivateKey(blk.Bytes)

	} else {
		return nil, err
	}
}

func createAccount(ctx context.Context, le *acmez.Client) (acct acme.Account, err error) {
	acct.PrivateKey, err = createKey(config.LetsEncrypt.AccountKey)
	if err != nil {
		return acct, err
	}

	f, err := os.Open(config.LetsEncrypt.Account)
	if err == nil {
		defer f.Close()
		return acct, json.NewDecoder(f).Decode(&acct)
	}

	if config.LetsEncrypt.Email != "" {
		acct.Contact = append(acct.Contact, "mailto:"+config.LetsEncrypt.Email)
	}
	acct.TermsOfServiceAgreed = true
	acct, err = le.NewAccount(ctx, acct)
	if err != nil {
		return acct, err
	}

	json, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return acct, err
	}

	err = ioutil.WriteFile(config.LetsEncrypt.Account, json, 0600)
	return acct, err
}

func createCertificate(ctx context.Context, le *acmez.Client, acct acme.Account, key crypto.Signer, domain string) error {
	certs, err := le.ObtainCertificate(ctx, acct, key, []string{domain})
	if err != nil {
		return err
	}

	for _, acme := range certs {
		return ioutil.WriteFile(config.Certificate, acme.ChainPEM, 0600)
	}
	return errors.New("no certificates obtained")
}
