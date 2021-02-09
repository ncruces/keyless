package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/coreos/go-systemd/v22/daemon"
)

func main() {
	if err := loadConfig(); err != nil {
		log.Fatalln(err)
	}

	if len(os.Args) > 1 && os.Args[1] == "setup" {
		// run the interactive setup and exit
		interactiveSetup()
		return
	}
	if err := checkSetup(); err != nil {
		// ask the user to run the interactive setup
		log.Println("letsencrypt:", err)
		log.Fatalln("please, run:", os.Args[0], "setup")
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
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
	} else {
		var err error
		dnsconn, err = net.ListenPacket("udp", "localhost:5353")
		if err != nil {
			log.Fatalln("dns server:", err)
		}
		defer dnsconn.Close()
	}

	httpsrv, err := httpInit()
	if err != nil {
		log.Fatalln("http server:", err)
	}
	httpsrv.Addr = "localhost:8080"
	httpsrv.BaseContext = func(_ net.Listener) context.Context { return ctx }

	go func() {
		var err error
		if httpln == nil {
			err = httpsrv.ListenAndServe()
		} else {
			err = httpsrv.ServeTLS(httpln, "", "")
		}
		if !errors.Is(err, http.ErrServerClosed) {
			log.Fatalln("http server:", err)
		}
	}()

	go func() {
		err := dnsServe(dnsconn)
		// TODO: replace with errors.Is(err, net.ErrClosed) after Go 1.16
		if err != nil && !strings.HasSuffix(err.Error(), "use of closed network connection") {
			log.Fatalln("dns server:", err)
		}
	}()

	daemon.SdNotify(true, daemon.SdNotifyReady)

	<-shutdown
	go func() {
		log.Fatalln(<-shutdown)
	}()
	if err := dnsconn.Close(); err != nil {
		log.Fatalln("close dns connection:", err)
	}
	if err := httpsrv.Shutdown(ctx); err != nil {
		log.Fatalln("shutdown http server:", err)
	}
}

func logError(err error) {
	if err != nil {
		log.Println(err)
	}
}
