package keyless

import (
	"crypto/tls"
	"log"
	"net/http"
	"os"
)

func ExampleGetCertificate() {
	auth, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	srv := http.Server{
		Addr: "localhost:8443",
		TLSConfig: &tls.Config{
			GetCertificate: GetCertificate(os.Getenv("API_URL"), auth),
		},
	}

	err = srv.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal(err)
	}

	// Output:
}
