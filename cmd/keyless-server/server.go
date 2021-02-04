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

	fs := activation.Files(true)
	if len(fs) > 2 {
		log.Fatalln("activation: unexpected number of files")
	}

	var httpln net.Listener
	var dnsconn net.PacketConn
	if len(fs) > 0 {
		var err error
		httpln, err = net.FileListener(fs[0])
		if err != nil {
			log.Fatalln("activation:", err)
		}
		fs[0].Close()
	}
	if len(fs) > 1 {
		var err error
		dnsconn, err = net.FilePacketConn(fs[1])
		if err != nil {
			log.Fatalln("activation:", err)
		}
		fs[1].Close()
	}

	http.Handle(config.Handler+"/certificate", http.HandlerFunc(certificateHandler))
	http.Handle(config.Handler+"/sign", http.HandlerFunc(signingHandler))

	server, err := origin.NewServer(config.Cloudflare.Cert, config.Cloudflare.Key, config.Cloudflare.PullCA)
	if err != nil {
		log.Fatalln("create http server:", err)
	}
	server.Addr = "localhost:8080"
	server.BaseContext = func(_ net.Listener) context.Context { return ctx }

	go func() {
		var err error
		if httpln == nil {
			err = server.ListenAndServe()
		} else {
			err = server.ServeTLS(httpln, "", "")
		}
		if err != http.ErrServerClosed {
			log.Fatalln("http server:", err)
		}
	}()

	go func() {
		var err error
		if dnsconn == nil {
			dnsconn, err = net.ListenPacket("udp", "localhost:5353")
			if err != nil {
				log.Fatalln("dns server:", err)
			}
			defer dnsconn.Close()
		}
		dnsServe(dnsconn)
	}()

	daemon.SdNotify(true, daemon.SdNotifyReady)

	<-shutdown
	go func() {
		log.Fatalln("received second signal:", <-shutdown)
	}()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalln("shutdown http server:", err)
	}
}
