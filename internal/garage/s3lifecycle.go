/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package garage

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// LifecycleConfiguration is the S3 wire format for bucket lifecycle. We
// expose only the subset of fields Garage accepts; unsupported AWS fields
// (transitions, NoncurrentVersion*, tag filters) are deliberately omitted.
type LifecycleConfiguration struct {
	XMLName xml.Name           `xml:"LifecycleConfiguration"`
	Xmlns   string             `xml:"xmlns,attr,omitempty"`
	Rules   []LifecycleXMLRule `xml:"Rule"`
}

// LifecycleXMLRule mirrors the S3 Rule element. AbortIncompleteMultipartUpload
// and Expiration are pointers so empty actions are not emitted.
type LifecycleXMLRule struct {
	ID                             string                  `xml:"ID"`
	Status                         string                  `xml:"Status"`
	Filter                         *LifecycleXMLFilter     `xml:"Filter,omitempty"`
	Expiration                     *LifecycleXMLExpiration `xml:"Expiration,omitempty"`
	AbortIncompleteMultipartUpload *LifecycleXMLAbort      `xml:"AbortIncompleteMultipartUpload,omitempty"`
}

// LifecycleXMLFilter holds at most one direct child or a single And block.
// AWS S3 requires And when combining multiple criteria.
type LifecycleXMLFilter struct {
	Prefix                *string          `xml:"Prefix,omitempty"`
	ObjectSizeGreaterThan *int64           `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64           `xml:"ObjectSizeLessThan,omitempty"`
	And                   *LifecycleXMLAnd `xml:"And,omitempty"`
}

// LifecycleXMLAnd combines multiple filter criteria.
type LifecycleXMLAnd struct {
	Prefix                *string `xml:"Prefix,omitempty"`
	ObjectSizeGreaterThan *int64  `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64  `xml:"ObjectSizeLessThan,omitempty"`
}

// LifecycleXMLExpiration carries either Days or Date (mutually exclusive).
type LifecycleXMLExpiration struct {
	Days *int32  `xml:"Days,omitempty"`
	Date *string `xml:"Date,omitempty"` // RFC3339, midnight UTC
}

// LifecycleXMLAbort triggers cleanup of stale multipart uploads.
type LifecycleXMLAbort struct {
	DaysAfterInitiation int32 `xml:"DaysAfterInitiation"`
}

const lifecycleQueryParam = "lifecycle"

// S3LifecycleClient calls the three S3 lifecycle endpoints Garage exposes.
// All requests are path-style; vhost-style is not used because the operator
// targets Garage in-cluster by service FQDN.
type S3LifecycleClient struct {
	HTTPClient      *http.Client
	Endpoint        string // e.g. http://garage.default.svc.cluster.local:3900
	Region          string // SigV4 region; Garage default is "garage"
	AccessKeyID     string
	SecretAccessKey string

	// Overrides the clock used to timestamp signatures. Tests inject a
	// fixed time to make signatures deterministic; production leaves it nil.
	now func() time.Time
}

// NewS3LifecycleClient builds a client. Endpoint must include scheme.
func NewS3LifecycleClient(endpoint, region, accessKeyID, secretAccessKey string) *S3LifecycleClient {
	return &S3LifecycleClient{
		HTTPClient:      &http.Client{Timeout: 30 * time.Second},
		Endpoint:        strings.TrimRight(endpoint, "/"),
		Region:          region,
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
	}
}

// GetLifecycle returns the current lifecycle configuration on the bucket, or
// nil when no lifecycle is set (S3 returns NoSuchLifecycleConfiguration).
func (c *S3LifecycleClient) GetLifecycle(ctx context.Context, bucket string) (*LifecycleConfiguration, error) {
	req, err := c.newRequest(ctx, http.MethodGet, bucket, nil)
	if err != nil {
		return nil, err
	}
	resp, body, err := c.do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		var cfg LifecycleConfiguration
		if err := xml.Unmarshal(body, &cfg); err != nil {
			return nil, fmt.Errorf("decode lifecycle xml: %w", err)
		}
		return &cfg, nil
	case http.StatusNotFound:
		// NoSuchLifecycleConfiguration; treat as not set.
		return nil, nil
	default:
		return nil, s3Error(resp.StatusCode, body)
	}
}

// PutLifecycle replaces the lifecycle configuration on the bucket. cfg must
// be non-nil and contain at least one rule.
func (c *S3LifecycleClient) PutLifecycle(ctx context.Context, bucket string, cfg *LifecycleConfiguration) error {
	if cfg == nil {
		return fmt.Errorf("lifecycle configuration is required")
	}
	cfg.Xmlns = "http://s3.amazonaws.com/doc/2006-03-01/"
	body, err := xml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode lifecycle xml: %w", err)
	}
	body = append([]byte(xml.Header), body...)

	req, err := c.newRequest(ctx, http.MethodPut, bucket, body)
	if err != nil {
		return err
	}
	// AWS requires Content-MD5 for PutBucketLifecycleConfiguration. Garage
	// may not enforce it, but matching the spec keeps us interoperable.
	sum := md5.Sum(body)
	req.Header.Set("Content-MD5", base64.StdEncoding.EncodeToString(sum[:]))
	req.Header.Set("Content-Type", "application/xml")

	resp, respBody, err := c.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return s3Error(resp.StatusCode, respBody)
	}
	return nil
}

// DeleteLifecycle removes the lifecycle configuration on the bucket.
func (c *S3LifecycleClient) DeleteLifecycle(ctx context.Context, bucket string) error {
	req, err := c.newRequest(ctx, http.MethodDelete, bucket, nil)
	if err != nil {
		return err
	}
	resp, body, err := c.do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 && resp.StatusCode != http.StatusNotFound {
		return s3Error(resp.StatusCode, body)
	}
	return nil
}

func (c *S3LifecycleClient) newRequest(ctx context.Context, method, bucket string, body []byte) (*http.Request, error) {
	if bucket == "" {
		return nil, fmt.Errorf("bucket is required")
	}
	u, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint: %w", err)
	}
	u.Path = "/" + bucket
	u.RawQuery = lifecycleQueryParam

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.ContentLength = int64(len(body))
	}
	clock := c.now
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if err := signSigV4(req, body, c.AccessKeyID, c.SecretAccessKey, c.Region, "s3", clock()); err != nil {
		return nil, fmt.Errorf("sign request: %w", err)
	}
	return req, nil
}

func (c *S3LifecycleClient) do(req *http.Request) (*http.Response, []byte, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, fmt.Errorf("read response: %w", err)
	}
	return resp, body, nil
}

// S3Error captures a non-2xx S3 response.
type S3Error struct {
	StatusCode int
	Body       string
}

func (e *S3Error) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("s3 request failed: status %d", e.StatusCode)
	}
	return fmt.Sprintf("s3 request failed: status %d: %s", e.StatusCode, e.Body)
}

func s3Error(status int, body []byte) error {
	const cap = 1024
	if len(body) > cap {
		body = body[:cap]
	}
	return &S3Error{StatusCode: status, Body: string(body)}
}

// signSigV4 signs req using AWS Signature Version 4. body may be nil for an
// empty payload. The implementation handles only what the lifecycle endpoints
// need: path-style URLs, single Host header, no streaming.
func signSigV4(req *http.Request, body []byte, accessKey, secretKey, region, service string, now time.Time) error {
	if accessKey == "" || secretKey == "" {
		return fmt.Errorf("missing access credentials")
	}

	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := hashSHA256(body)
	req.Header.Set("Host", req.URL.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonicalURI := req.URL.EscapedPath()
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQuery := canonicalQueryString(req.URL.Query())

	signedHeaders, canonicalHeaders := canonicalHeaderList(req.Header)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashSHA256([]byte(canonicalRequest)),
	}, "\n")

	signingKey := deriveSigningKey(secretKey, dateStamp, region, service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	auth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessKey, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", auth)
	return nil
}

func canonicalQueryString(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, awsURIEncode(k, true)+"="+awsURIEncode(v, true))
		}
	}
	return strings.Join(parts, "&")
}

// canonicalHeaderList returns the SignedHeaders (semicolon-separated, sorted,
// lowercase header names) and the canonical headers block (each header on
// its own line, sorted, lowercase name, trimmed value).
func canonicalHeaderList(h http.Header) (signed string, canonical string) {
	type kv struct{ k, v string }
	pairs := make([]kv, 0, len(h))
	for k, vals := range h {
		lk := strings.ToLower(k)
		// Per RFC, header values must be trimmed and internal whitespace collapsed.
		joined := strings.Join(vals, ",")
		pairs = append(pairs, kv{k: lk, v: trimAll(joined)})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].k < pairs[j].k })

	names := make([]string, 0, len(pairs))
	var b strings.Builder
	for _, p := range pairs {
		names = append(names, p.k)
		b.WriteString(p.k)
		b.WriteByte(':')
		b.WriteString(p.v)
		b.WriteByte('\n')
	}
	return strings.Join(names, ";"), b.String()
}

// awsURIEncode encodes per AWS spec. RFC 3986 unreserved chars are not
// escaped; everything else is percent-encoded uppercase. When encodeSlash
// is false, '/' is preserved (used for object keys, not query params).
func awsURIEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z',
			c >= 'a' && c <= 'z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func trimAll(s string) string {
	out := make([]byte, 0, len(s))
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !prevSpace {
				out = append(out, ' ')
				prevSpace = true
			}
			continue
		}
		out = append(out, c)
		prevSpace = false
	}
	return strings.TrimSpace(string(out))
}

func hashSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	return hmacSHA256(kService, "aws4_request")
}
