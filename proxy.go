package main

import (
	"errors"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/alecthomas/kingpin/v2"
	"github.com/aws/aws-sdk-go/aws/credentials"
	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	log "github.com/rs/zerolog/log"
)

// Options for aws-s3-reverse-proxy command line arguments
type Options struct {
	ListenAddr     string
	AwsCredentials []string
	Region         string
}

// NewOptions defines and parses the raw command line arguments
func NewOptions() Options {
	var opts Options
	kingpin.Flag("listen-addr", "address:port to listen for requests on (env - LISTEN_ADDR)").Default(":8099").Envar("LISTEN_ADDR").StringVar(&opts.ListenAddr)
	kingpin.Flag("aws-credentials", "set of AWS credentials (env - AWS_CREDENTIALS)").PlaceHolder("\"AWS_ACCESS_KEY_ID,AWS_SECRET_ACCESS_KEY\"").Envar("AWS_CREDENTIALS").StringsVar(&opts.AwsCredentials)
	kingpin.Flag("aws-region", "send requests to this AWS S3 region (env - AWS_REGION)").Envar("AWS_REGION").Default("eu-central-1").StringVar(&opts.Region)
	kingpin.Parse()
	return opts
}

// NewAwsS3ReverseProxy parses all options and creates a new HTTP Handler
func NewAwsS3ReverseProxy(opts Options) (*Handler, error) {

	parsedAwsCredentials := make(map[string]string)
	for _, cred := range opts.AwsCredentials {
		d := strings.Split(cred, ",")
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
		UpstreamScheme: "https",
		AWSCredentials: parsedAwsCredentials,
		Signers:        signers,
	}
	return handler, nil
}

func main() {
	opts := NewOptions()
	handler, err := NewAwsS3ReverseProxy(opts)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to create AWS S3 reverse proxy")
	}

	log.Info().Msg("Auto-detecting S3 endpoint based on region: " + handler.UpstreamScheme + "://s3.{region}.amazonaws.com")

	log.Info().Msg("Parsed " + strconv.Itoa(len(handler.AWSCredentials)) + " AWS credential sets.")

	log.Info().Msg("Listening for HTTP connections on " + opts.ListenAddr)

	go func() {
		log.Info().Msg("s3p is live")
		if err := http.ListenAndServe(opts.ListenAddr, ResponseLoggerMiddleware(RequestLoggerMiddleware(handler))); err != nil && errors.Is(err, http.ErrServerClosed) {
			log.Info().Msgf("s3c server forced to shut down")
		}
	}()
	// Safe shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info().Msg("shutting down s3c server...")
}
