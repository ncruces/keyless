package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
	"github.com/ncruces/go-cloudflare/origin"
)

var shutdown = make(chan os.Signal, 1)

func init() {
	signal.Notify(shutdown, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
}

func main() {
	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}

	if len(os.Args) > 1 && os.Args[1] == "renew" {
		renewCertificate()
		return
	}

	if err := loadCertificate(); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ln, err := activation.Listeners()
	if err != nil {
		log.Fatalln("get listeners:", err)
	}
	if len(ln) > 1 {
		log.Fatalln("get listeners: unexpected number of listeners")
	}

	http.Handle(config.CertHandler, http.HandlerFunc(certificateHandler))
	http.Handle(config.SignHandler, http.HandlerFunc(signingHandler))

	server, err := origin.NewServer(config.Cloudflare.Cert, config.Cloudflare.Key, config.Cloudflare.PullCA)
	if err != nil {
		log.Fatalln("create server:", err)
	}
	server.Addr = "localhost:http"
	server.BaseContext = func(_ net.Listener) context.Context { return ctx }

	go func() {
		var err error
		if len(ln) == 0 {
			err = server.ListenAndServe()
		} else {
			err = server.ServeTLS(ln[0], "", "")
		}
		if err != http.ErrServerClosed {
			log.Fatalln("server:", err)
		}
	}()

	daemon.SdNotify(true, daemon.SdNotifyReady)

	<-shutdown
	go func() {
		log.Fatalln("received second signal:", <-shutdown)
	}()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalln("shutdown server:", err)
	}
}
