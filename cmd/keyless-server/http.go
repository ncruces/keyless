package main

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"net/http"
	"time"
)

func httpInit() (*http.Server, error) {
	cert, err := tls.LoadX509KeyPair(config.API.Certificate, config.API.Key)
	if err != nil {
		return nil, err
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, err
	}

	cfg := tls.Config{}
	cfg.Certificates = append(cfg.Certificates, cert)

	if config.API.ClientCA != "" {
		cert, err := ioutil.ReadFile(config.API.ClientCA)
		if err != nil {
			return nil, err
		}

		cfg.ClientCAs = x509.NewCertPool()
		cfg.ClientCAs.AppendCertsFromPEM(cert)
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	var mux http.ServeMux
	mux.Handle(config.API.Handler+"/sign", http.HandlerFunc(signingHandler))
	mux.Handle(config.API.Handler+"/certificate", http.HandlerFunc(certificateHandler))

	server := http.Server{
		Handler:      &mux,
		TLSConfig:    &cfg,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  10 * time.Minute,
	}

	return &server, nil
}

func certificateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	http.ServeFile(w, r, config.Certificate)
}

func signingHandler(w http.ResponseWriter, r *http.Request) {
	sendError := func(status int) {
		http.Error(w, http.StatusText(status), status)
	}

	query := r.URL.Query()

	key, ok := privateKeys[query.Get("key")]
	if !ok {
		sendError(http.StatusNotFound)
		return
	}

	var hash crypto.Hash
	if h := query.Get("hash"); h != "" {
		for hash = crypto.MD4; ; hash++ {
			if hash > crypto.BLAKE2b_512 {
				sendError(http.StatusNotFound)
				return
			}
			if hash.String() == h && hash.Available() {
				// found
				break
			}
		}
	}

	var digest [65]byte
	n, err := io.ReadFull(r.Body, digest[:])
	if err != io.ErrUnexpectedEOF {
		sendError(http.StatusBadRequest)
		return
	}

	signature, err := key.Sign(rand.Reader, digest[:n], hash)
	if err != nil {
		sendError(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(signature)
}
