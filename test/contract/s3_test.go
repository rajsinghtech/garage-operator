//go:build garagecontract

package contract

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// s3PutObject uploads one object with a minimal AWS SigV4 signature (region
// "garage"), enough to make a bucket non-empty without an S3 SDK dependency.
func s3PutObject(t *testing.T, addr, accessKey, secretKey, bucket, key string, body []byte) {
	t.Helper()
	now := time.Now().UTC()
	amzDate, day := now.Format("20060102T150405Z"), now.Format("20060102")
	payloadHash := sha256Hex(body)
	path := "/" + bucket + "/" + key
	canonical := fmt.Sprintf("PUT\n%s\n\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n\nhost;x-amz-content-sha256;x-amz-date\n%s",
		path, addr, payloadHash, amzDate, payloadHash)
	scope := day + "/garage/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	signingKey := hmacSHA256([]byte("AWS4"+secretKey), day)
	for _, part := range []string{"garage", "s3", "aws4_request"} {
		signingKey = hmacSHA256(signingKey, part)
	}
	signature := hex.EncodeToString(hmacSHA256(signingKey, toSign))

	req, err := http.NewRequest(http.MethodPut, "http://"+addr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("x-amz-content-sha256", payloadHash)
	req.Header.Set("Authorization", fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s", accessKey, scope, signature))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("S3 PutObject %s: HTTP %d: %s", path, resp.StatusCode, buf.String())
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
