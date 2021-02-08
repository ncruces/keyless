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
	"net"
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

// Checks that LetsEncrypt is setup correctly at startup.
// Load private keys (master and legacy) into memory.
// Rotating the master key requires a process restart.
func loadLetsEncrypt() error {
	_, err := loadAccount()
	if err != nil {
		return err
	}
	return loadCertificate()
}

// Setup LetsEncrypt interactively.
func setupLetsEncrypt() {
	fmt.Println("Running setup...")
	fmt.Println()

	ctx := context.Background()
	client := &acmez.Client{
		Client: &acme.Client{},
		ChallengeSolvers: map[string]acmez.Solver{
			acme.ChallengeTypeDNS01: &dnsSolver,
		},
	}

	acct, err := loadAccount()
	if err == nil {
		fmt.Println("Using the existing Let's Encrypt account.")
	} else {
		acct, err = createAccount(ctx, client)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if client.Directory == "" {
		if strings.HasPrefix(acct.Location, letsencryptProduction) {
			client.Directory = letsencryptProduction + "directory"
		} else {
			client.Directory = letsencryptStaging + "directory"
		}
	}

	master, err := createKey("master", config.MasterKey)
	if err != nil {
		log.Fatalln(err)
	}

	app := filepath.Base(os.Args[0])
	domain := strings.TrimSuffix(config.Domain, ".")
	nameserver := strings.TrimSuffix(config.Nameserver, ".")
	fmt.Println()
	fmt.Println("Starting DNS server for domain validation...")
	fmt.Println("Please, ensure that:")
	fmt.Printf(" - NS records for %s point to %s\n", domain, nameserver)
	fmt.Printf(" - %s is reachable from the internet on UDP %s:53\n", app, nameserver)
	fmt.Print("Continue? ")
	fmt.Scanln()
	fmt.Println()

	conn, err := net.ListenPacket("udp", config.Nameserver+":53")
	if err != nil {
		if conn, _ = net.ListenPacket("udp", ":53"); conn == nil {
			log.Fatalln(err)
		}
	}
	defer conn.Close()
	go dnsServe(conn)

	fmt.Println("Obtaining a certificate...")
	err = createCertificate(ctx, client, acct, master, "*."+domain)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println()
	fmt.Println("Done!")
}

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

func createKey(keyName, keyFile string) (*ecdsa.PrivateKey, error) {
	if buf, err := ioutil.ReadFile(keyFile); os.IsNotExist(err) {
		fmt.Println("Creating a new", keyName, "private key...")

		err := os.MkdirAll(filepath.Dir(keyFile), 0700)
		if err != nil {
			return nil, err
		}

		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}

		pem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		err = ioutil.WriteFile(keyFile, pem, 0400)
		if err != nil {
			return nil, err
		}

		return key, nil

	} else {
		fmt.Println("Using the existing", keyName, "private key...")
		if err != nil {
			return nil, err
		}

		blk, _ := pem.Decode(buf)
		if blk == nil {
			return nil, errors.New("no PEM data found")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
}

func createAccount(ctx context.Context, client *acmez.Client) (acct acme.Account, err error) {
	fmt.Println("Creating a new Let's Encrypt account...")

	err = os.MkdirAll(filepath.Dir(config.LetsEncrypt.Account), 0700)
	if err != nil {
		return acct, err
	}

	acct.PrivateKey, err = createKey("account", config.LetsEncrypt.AccountKey)
	if err != nil {
		return acct, err
	}

	var answer string

	fmt.Println()
	fmt.Print("Accept Let's Encrypt ToS? [y/n]: ")
	fmt.Scanln(&answer)
	if answer != "y" {
		return acct, errors.New("Did not accept Let's Encrypt ToS")
	}

	fmt.Print("Use the production API? [y/n]: ")
	fmt.Scanln(&answer)
	if answer == "y" {
		client.Directory = letsencryptProduction + "directory"
	} else {
		client.Directory = letsencryptStaging + "directory"
	}

	fmt.Print("Enter an email address: ")
	fmt.Scanln(&answer)
	if answer != "" {
		acct.Contact = append(acct.Contact, "mailto:"+answer)
	}
	fmt.Println()

	acct.TermsOfServiceAgreed = true
	acct, err = client.NewAccount(ctx, acct)
	if err != nil {
		return acct, err
	}

	json, err := json.MarshalIndent(acct, "", "  ")
	if err != nil {
		return acct, err
	}

	err = ioutil.WriteFile(config.LetsEncrypt.Account, json, 0400)
	return acct, err
}

func createCertificate(ctx context.Context, le *acmez.Client, acct acme.Account, key crypto.Signer, domain string) error {
	certs, err := le.ObtainCertificate(ctx, acct, key, []string{domain})
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
