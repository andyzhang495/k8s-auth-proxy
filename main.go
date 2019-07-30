package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	authorizedToken = "FQiUnkxCTnVTMTzMzpC6"
	upstream        = "https://47.102.63.109:6443"
	remoteUser      = "229736241737041599"
)

func main() {
	fmt.Println("Starting server on 127.0.0.1:8001")

	// setting up CA
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	cwd, _ := os.Getwd()
	caPath := cwd + "/certs/kunkka.ca"
	certs, err := ioutil.ReadFile(caPath)

	if err != nil {
		log.Error().Err(err).Str("ca_path", caPath).Msg("Cannot read CA file")
		os.Exit(1)
	}

	ok := rootCAs.AppendCertsFromPEM(certs)
	if !ok {
		log.Fatal().Msg("Cannot add CA to pool")
		os.Exit(1)
	}

	clientCrt, err := tls.LoadX509KeyPair(cwd+"/certs/kunkka.crt", cwd+"/certs/kunkka.key")
	if err != nil {
		log.Error().Err(err).Msg("Load client cert failed")
		os.Exit(1)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCrt},
		RootCAs:      rootCAs,
	}
	tlsConfig.BuildNameToCertificate()
	c := http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}

	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if len(auth) == 0 || string(auth) != "Bearer "+authorizedToken {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "Unauthorized")
			log.Info().Str("from", r.RemoteAddr).Interface("authorization", auth).Msg("Unauthorized request")
			return
		}
		log.Debug().Interface("request", r.Header).Msg("Request")
		upstream := upstream
		nr, err := http.NewRequest(r.Method, upstream+r.URL.String(), r.Body)
		if err != nil {
			log.Error().Err(err).Msg("Error constructing request")
		}
		nr.Header.Add("X-Remote-User", remoteUser)
		resp, err := c.Do(nr)
		if err != nil {
			log.Error().Err(err).Msg("Error requesting upstream")
		}
		log.Debug().Interface("response", resp.Status).Msg("New request")
		for k, v := range resp.Header {
			for _, e := range v {
				w.Header().Add(k, e)
			}
		}
		w.WriteHeader(resp.StatusCode)
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Error().Err(err).Msg("Can't read response body from k8s api")
		}
		w.Write(body)
	})

	log.Fatal().Err(http.ListenAndServe("127.0.0.1:8001", nil)).Msg("Server error")
}
