package main

import (
    "crypto/tls"
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    zip_streamer "github.com/scosman/zipstreamer/zip_streamer"

    "golang.org/x/crypto/acme/autocert"
)

func main() {
    zipServer := zip_streamer.NewServer()
    zipServer.Compression = (os.Getenv("ZS_COMPRESSION") == "DEFLATE")
    zipServer.ListfileUrlPrefix = os.Getenv("ZS_LISTFILE_URL_PREFIX")

    certManager := autocert.Manager{
        Prompt:     autocert.AcceptTOS,
        HostPolicy: autocert.HostWhitelist("zip-streamer.cliped.io"), //Your domain here
        Cache:      autocert.DirCache("certs"),            //Folder for storing certificates
    }

    httpServer := &http.Server{
        Addr: ":https",
        TLSConfig: &tls.Config{
            GetCertificate: certManager.GetCertificate,
            MinVersion: tls.VersionTLS12, // improves cert reputation score at https://www.ssllabs.com/ssltest/
        },
        Handler:     zipServer,
        ReadTimeout: 10 * time.Second,
    }

    shutdownChannel := make(chan os.Signal, 10)
    go func() {
		log.Printf("Running server")
        err := http.ListenAndServe(":http", certManager.HTTPHandler(nil))
        if err != nil && err != http.ErrServerClosed {
            log.Printf("Server Error: %s", err)
        }
        shutdownChannel <- syscall.SIGUSR1
    }()

    log.Fatal(httpServer.ListenAndServeTLS("", ""))

    // Listen for os signal for graceful shutdown
    signal.Notify(shutdownChannel, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)

    // Wait for shutdown signal, then shut down
    shutdownSignal := <-shutdownChannel
    log.Printf("Received signal (%s), shutting down...", shutdownSignal.String())
    httpServer.Shutdown(context.Background())

    // Exit was not expected, return non 0 exit code
    if shutdownSignal == syscall.SIGUSR1 {
        os.Exit(1)
    }
}