package main

import (
	"crypto"
	"crypto/rand"
	"io"
	"net/http"
)

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
