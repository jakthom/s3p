package main

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"

	v4 "github.com/aws/aws-sdk-go/aws/signer/v4"
	"github.com/rs/zerolog/log"
)

var awsAuthorizationCredentialRegexp = regexp.MustCompile("Credential=([a-zA-Z0-9]+)/[0-9]+/([a-z]+-?[a-z]+-?[0-9]+)/s3/aws4_request")
var awsAuthorizationSignedHeadersRegexp = regexp.MustCompile("SignedHeaders=([a-zA-Z0-9;-]+)")

// Handler is a special handler that re-signs any AWS S3 request and sends it upstream
type Handler struct {

	// http or https
	UpstreamScheme string

	// Upstream S3 endpoint URL
	UpstreamEndpoint string

	// AWS Credentials, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
	AWSCredentials map[string]string

	// AWS Signature v4
	Signers map[string]*v4.Signer

	// Reverse Proxy
	Proxy *httputil.ReverseProxy
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	proxyReq, err := h.buildUpstreamRequest(r)
	if err != nil {
		log.Error().Err(err).Msg("unable to proxy request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	url := url.URL{Scheme: proxyReq.URL.Scheme, Host: proxyReq.Host}
	proxy := httputil.NewSingleHostReverseProxy(&url)
	proxy.FlushInterval = 1
	proxy.ServeHTTP(w, proxyReq)
}

func (h *Handler) sign(signer *v4.Signer, req *http.Request, region string) error {
	return h.signWithTime(signer, req, region, time.Now())
}

func (h *Handler) signWithTime(signer *v4.Signer, req *http.Request, region string, signTime time.Time) error {
	body := bytes.NewReader([]byte{})
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}

	_, err := signer.Sign(req, body, "s3", region, signTime)
	return err
}

func copyHeaderWithoutOverwrite(dst http.Header, src http.Header) {
	for k, v := range src {
		if _, ok := dst[k]; !ok {
			for _, vv := range v {
				dst.Add(k, vv)
			}
		}
	}
}

func (h *Handler) validateIncomingHeaders(req *http.Request) (string, string, error) {
	amzDateHeader := req.Header["X-Amz-Date"]
	if len(amzDateHeader) != 1 {
		return "", "", fmt.Errorf("X-Amz-Date header missing or set multiple times: %v", req)
	}

	authorizationHeader := req.Header["Authorization"]
	if len(authorizationHeader) != 1 {
		return "", "", fmt.Errorf("Authorization header missing or set multiple times: %v", req)
	}
	match := awsAuthorizationCredentialRegexp.FindStringSubmatch(authorizationHeader[0])
	if len(match) != 3 {
		return "", "", fmt.Errorf("invalid Authorization header: Credential not found: %v", req)
	}
	receivedAccessKeyID := match[1]
	region := match[2]

	// Validate the received Credential (ACCESS_KEY_ID) is allowed
	for accessKeyID := range h.AWSCredentials {
		if subtle.ConstantTimeCompare([]byte(receivedAccessKeyID), []byte(accessKeyID)) == 1 {
			return accessKeyID, region, nil
		}
	}
	return "", "", fmt.Errorf("invalid AccessKeyID in Credential: %v", req)
}

func (h *Handler) assembleUpstreamReq(signer *v4.Signer, req *http.Request, region string) (*http.Request, error) {
	upstreamEndpoint := h.UpstreamEndpoint
	if len(upstreamEndpoint) == 0 {
		upstreamEndpoint = fmt.Sprintf("s3.%s.amazonaws.com", region)
		log.Info().Msg("Using " + upstreamEndpoint + " as upstream endpoint")
	}

	proxyURL := *req.URL
	proxyURL.Scheme = h.UpstreamScheme
	proxyURL.Host = upstreamEndpoint
	proxyURL.RawPath = req.URL.Path
	proxyReq, err := http.NewRequest(req.Method, proxyURL.String(), req.Body)
	if err != nil {
		return nil, err
	}
	if val, ok := req.Header["Content-Type"]; ok {
		proxyReq.Header["Content-Type"] = val
	}
	if val, ok := req.Header["Content-Md5"]; ok {
		proxyReq.Header["Content-Md5"] = val
	}

	// Sign the upstream request
	if err := h.sign(signer, proxyReq, region); err != nil {
		return nil, err
	}

	// Add origin headers after request is signed (no overwrite)
	copyHeaderWithoutOverwrite(proxyReq.Header, req.Header)

	return proxyReq, nil
}

// Do validates the incoming request and create a new request for an upstream server
func (h *Handler) buildUpstreamRequest(req *http.Request) (*http.Request, error) {

	// Validate incoming headers and extract AWS_ACCESS_KEY_ID
	accessKeyID, region, err := h.validateIncomingHeaders(req)
	if err != nil {
		return nil, err
	}

	// Get the AWS Signature signer for this AccessKey
	signer := h.Signers[accessKeyID]

	// Assemble a new upstream request
	proxyReq, err := h.assembleUpstreamReq(signer, req, region)
	if err != nil {
		return nil, err
	}

	// Disable Go's "Transfer-Encoding: chunked" madness
	proxyReq.ContentLength = req.ContentLength

	return proxyReq, nil
}
