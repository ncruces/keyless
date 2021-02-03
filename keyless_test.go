package keyless

import (
	"crypto/tls"
	"net/http"
	"os"
	"testing"
)

func TestGetCertificate(t *testing.T) {
	auth, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		t.Fatal(err)
	}

	srv := http.Server{
		Addr: "localhost:8443",
		TLSConfig: &tls.Config{
			GetCertificate: GetCertificate(os.Getenv("API_URL"), auth),
		},
	}

	err = srv.ListenAndServeTLS("", "")
	if err != nil {
		t.Fatal(err)
	}
}
