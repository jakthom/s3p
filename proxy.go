package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	_ "net/http/pprof"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/rs/zerolog/log"
)

// Options for aws-s3-reverse-proxy command line arguments
type Options struct {
	Debug            bool
	ListenAddr       string
	AwsCredentials   []string
	Region           string
	UpstreamEndpoint string
}

// NewOptions defines and parses the raw command line arguments
func NewOptions() Options {
	var opts Options
	kingpin.Flag("verbose", "enable additional logging (env - VERBOSE)").Envar("VERBOSE").Short('v').BoolVar(&opts.Debug)
	kingpin.Flag("listen-addr", "address:port to listen for requests on (env - LISTEN_ADDR)").Default(":8099").Envar("LISTEN_ADDR").StringVar(&opts.ListenAddr)
	kingpin.Flag("aws-credentials", "set of AWS credentials (env - AWS_CREDENTIALS)").PlaceHolder("\"AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY\"").Envar("AWS_CREDENTIALS").StringsVar(&opts.AwsCredentials)
	kingpin.Flag("aws-region", "send requests to this AWS S3 region (env - AWS_REGION)").Envar("AWS_REGION").Default("eu-central-1").StringVar(&opts.Region)
	kingpin.Parse()
	return opts
}

// NewAwsS3ReverseProxy parses all options and creates a new HTTP Handler
func NewAwsS3ReverseProxy(opts Options) (*Handler, error) {

	scheme := "https"

	parsedAwsCredentials := make(map[string]string)
	for _, cred := range opts.AwsCredentials {
		d := strings.Split(cred, ",")
		if len(d) != 2 || len(d[0]) < 16 || len(d[1]) < 1 {
			return nil, fmt.Errorf("Invalid AWS credentials. Did you separate them with a ',' or are they too short?")
		}
		parsedAwsCredentials[d[0]] = d[1]
	}

	signers := make(map[string]*v4.Signer)
	for accessKeyID, secretAccessKey := range parsedAwsCredentials {
		signers[accessKeyID] = v4.NewSigner(credentials.NewStaticCredentialsFromCreds(credentials.Value{
			AccessKeyID:     accessKeyID,
			SecretAccessKey: secretAccessKey,
		}))
	}

	handler := &Handler{
		Debug:            opts.Debug,
		UpstreamScheme:   scheme,
		UpstreamEndpoint: opts.UpstreamEndpoint,
		AWSCredentials:   parsedAwsCredentials,
		Signers:          signers,
	}
	return handler, nil
}

func main() {
	opts := NewOptions()
	handler, err := NewAwsS3ReverseProxy(opts)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create AWS S3 reverse proxy")
	}

	if len(handler.UpstreamEndpoint) > 0 {
		log.Info().Msg("Sending requests to upstream AWS S3 to endpoint " + handler.UpstreamScheme + "://" + handler.UpstreamEndpoint)
	} else {
		log.Info().Msg("Auto-detecting S3 endpoint based on region: " + handler.UpstreamScheme + "://s3.{region}.amazonaws.com")
	}

	log.Info().Msg("Parsed " + strconv.Itoa(len(handler.AWSCredentials)) + " AWS credential sets.")

	log.Info().Msg("Listening for HTTP connections on " + opts.ListenAddr)

	go func() {
		log.Info().Msg("s3p is running with version")
		if err := http.ListenAndServe(opts.ListenAddr, ResponseLoggerMiddleware(RequestLoggerMiddleware(handler))); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Info().Msgf("s3c server shut down")
		}
	}()
	// Safe shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down s3c server...")
}
