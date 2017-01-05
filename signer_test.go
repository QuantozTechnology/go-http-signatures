package httpsignatures_test

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/quantoztechnology/go-http-signatures"
)

var (
	// DefaultSha1Signer will sign requests with date using the SHA1 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha1Signer = httpsignatures.NewSigner("hmac-sha1")

	// DefaultSha256Signer will sign requests with date using the SHA256 algorithm.
	// Users are encouraged to create their own signer with the headers they require.
	DefaultSha256Signer = httpsignatures.NewSigner("hmac-sha256")
)

const (
	testSignature  = `keyId="Test",algorithm="hmac-sha256",signature="QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI="`
	testSha256Hash = `QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=`
	testSha1Hash   = `06tbjUif0/069JeDM7gWFUOjz04=`
	testKey        = "U29tZXRoaW5nUmFuZG9t"
	testDate       = "Thu, 05 Jan 2012 21:31:40 GMT"
	testKeyID      = "Test"

	ed25519TestSignature  = "yK9kWXAdp40MJzmjZnXhJcRaCClqgf9VpLrBUqCG6ywv85gCc0t4w/anI6zp5txyC13ICWMtNU22b+6AO1IQAA=="
	ed25519TestPrivateKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7aie8zrakLWKjqNAqbw1zZTIVdx3iQ6Y6wEihi1naKQ=="
	ed25519TestPublicKey  = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
)

// Signing

func TestSignSha1(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	err := DefaultSha1Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s httpsignatures.SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, httpsignatures.AlgorithmHmacSha1, s.Algorithm.Name)
	assert.Equal(t, httpsignatures.HeaderValues{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		"06tbjUif0/069JeDM7gWFUOjz04=",
		s.Signature,
	)
}

func TestSignSha256(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	err := DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s httpsignatures.SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, testKeyID, s.KeyID)
	assert.Equal(t, httpsignatures.AlgorithmHmacSha256, s.Algorithm.Name)
	assert.Equal(t, httpsignatures.HeaderValues{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		"QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=",
		s.Signature,
	)
}

func TestValidEd25119RequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	signer := httpsignatures.NewSigner("ed25519")
	err := signer.SignRequest(r, ed25519TestPublicKey, ed25519TestPrivateKey)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s httpsignatures.SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, ed25519TestPublicKey, s.KeyID)
	assert.Equal(t, httpsignatures.AlgorithmEd25519, s.Algorithm.Name)
	assert.Equal(t, httpsignatures.HeaderValues{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		ed25519TestSignature,
		s.Signature,
	)
}

func TestSignSha256OmitHeaderLeadingTrailingWhitespace(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"          Thu, 05 Jan 2012 21:31:40 GMT         "},
		},
	}

	// SignRequest places Signature header in request
	err := DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s httpsignatures.SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, httpsignatures.HeaderValues{"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
	assert.Equal(t,
		"QgoCZTOayhvFBl1QLXmFOZIVMXC0Dujs5ODsYVruDPI=",
		s.Signature,
	)
}

func TestSignSha256DoubleHeaderField(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Cache-Control": []string{"max-age=60", "must-revalidate"},
			"Date":          []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	// SignRequest places Signature header in request
	signer := httpsignatures.NewSigner("hmac-sha256", "cache-control", "date")
	err := signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	// Read Signature header from request and verify fields
	var s httpsignatures.SignatureParameters
	err = s.FromRequest(r)
	assert.Nil(t, err)
	assert.Equal(t, httpsignatures.HeaderValues{"cache-control": "max-age=60, must-revalidate",
		"date": "Thu, 05 Jan 2012 21:31:40 GMT"}, s.Headers)
}

func TestSignWithMissingDateHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{},
	}

	err := DefaultSha1Signer.AuthRequest(r, testKeyID, testKey)
	assert.EqualError(t, err, httpsignatures.ErrorMissingRequiredHeader+" 'date'")
	httpErr, _ := httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusBadRequest, httpErr)
}

func TestSignWithMissingHeader(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{"Thu, 05 Jan 2012 21:31:40 GMT"},
		},
	}

	s := httpsignatures.NewSigner("hmac-sha1", "foo")

	err := s.SignRequest(r, testKeyID, testKey)
	assert.EqualError(t, err, httpsignatures.ErrorMissingRequiredHeader+" 'foo'")
	httpErr, _ := httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusBadRequest, httpErr)
}

// Verifying
func keyLookUp(keyID string) (string, error) {
	return testKey, nil
}

func TestValidRequestIsValid(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	res, err := httpsignatures.VerifyRequest(r, keyLookUp, -1, []string{httpsignatures.AlgorithmHmacSha256})
	assert.True(t, res)
	assert.Nil(t, err)
}

func TestValidRequestHasRequiredAlgorithm(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	res, err := httpsignatures.VerifyRequest(r, keyLookUp, -1, []string{httpsignatures.AlgorithmHmacSha1})
	assert.False(t, res)
	assert.EqualError(t, err, httpsignatures.ErrorAlgorithmNotAllowed)
	httpErr, _ := httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusBadRequest, httpErr)

	res, err = httpsignatures.VerifyRequest(r, keyLookUp, -1, []string{httpsignatures.AlgorithmHmacSha1, httpsignatures.AlgorithmHmacSha256})
	assert.True(t, res)
	assert.Nil(t, err)
}

func TestNotValidIfRequestHeadersChange(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{testDate},
		},
	}
	err := DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	r.Header.Set("Date", "Thu, 05 Jan 2012 21:31:41 GMT")

	res, err := httpsignatures.VerifyRequest(r, keyLookUp, -1, []string{httpsignatures.AlgorithmHmacSha256})
	assert.False(t, res)
	assert.EqualError(t, err, httpsignatures.ErrorSignaturesDoNotMatch)
	httpErr, _ := httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusBadRequest, httpErr)
}

func TestNotValidIfClockSkewExceeded(t *testing.T) {
	allowedClockSkew := 300
	duration, err := time.ParseDuration(fmt.Sprintf("-%ds", allowedClockSkew))
	assert.Nil(t, err)
	r := &http.Request{
		Header: http.Header{
			"Date": []string{time.Now().Add(duration).Format(time.RFC1123)},
		},
	}
	err = DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	_, err = httpsignatures.VerifyRequest(r, keyLookUp, allowedClockSkew, []string{httpsignatures.AlgorithmHmacSha256})
	assert.Nil(t, err)

	_, err = httpsignatures.VerifyRequest(r, keyLookUp, allowedClockSkew-1, []string{httpsignatures.AlgorithmHmacSha256})
	assert.EqualError(t, err, httpsignatures.ErrorAllowedClockskewExceeded)
	httpErr, _ := httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusBadRequest, httpErr)

	_, err = httpsignatures.VerifyRequest(r, keyLookUp, 0, []string{httpsignatures.AlgorithmHmacSha256})
	assert.EqualError(t, err, httpsignatures.ErrorYouProbablyMisconfiguredAllowedClockSkew)
	httpErr, _ = httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusInternalServerError, httpErr)
}

func TestNotValidIfClockSkewExceededXDate(t *testing.T) {
	allowedClockSkew := 300
	duration, err := time.ParseDuration(fmt.Sprintf("-%ds", allowedClockSkew))
	assert.Nil(t, err)
	r := &http.Request{
		Header: http.Header{
			"X-Date": []string{time.Now().Add(duration).Format(time.RFC1123)},
		},
	}
	signer := httpsignatures.NewSigner("ed25519", "x-date")
	err = signer.SignRequest(r, ed25519TestPublicKey, ed25519TestPrivateKey)
	assert.Nil(t, err)

	keyLookUpProp := func(keyID string) (string, error) {
		return keyID, nil
	}

	_, err = httpsignatures.VerifyRequest(r, keyLookUpProp, allowedClockSkew, []string{httpsignatures.AlgorithmEd25519})
	assert.Nil(t, err)

	_, err = httpsignatures.VerifyRequest(r, keyLookUpProp, allowedClockSkew-1, []string{httpsignatures.AlgorithmEd25519})
	assert.EqualError(t, err, httpsignatures.ErrorAllowedClockskewExceeded)
}

func TestVerifyRequiredHeaderList(t *testing.T) {
	r := &http.Request{
		Header: http.Header{
			"Date": []string{time.Now().Format(time.RFC1123)},
		},
	}
	err := DefaultSha256Signer.SignRequest(r, testKeyID, testKey)
	assert.Nil(t, err)

	_, err = httpsignatures.VerifyRequest(r, keyLookUp, -1, []string{httpsignatures.AlgorithmHmacSha256}, "(request-target)")
	assert.EqualError(t, err, httpsignatures.ErrorRequiredHeaderNotInHeaderList+": '(request-target)'")
	httpErr, _ := httpsignatures.ErrorToHTTPCode(err.Error())
	assert.Equal(t, http.StatusBadRequest, httpErr)

	_, err = httpsignatures.VerifyRequest(r, keyLookUp, -1, []string{httpsignatures.AlgorithmHmacSha256}, "date")
	assert.Nil(t, err)
}

// Complete test:
func TestCompleteFunctionality(t *testing.T) {
	keyLookUpProp := func(keyID string) (string, error) {
		return keyID, nil
	}

	editRequestFunc := func(r *http.Request) {
		r.Host = "localhost"
		r.Header["Date"] = []string{time.Now().UTC().Format(time.RFC1123)}

		signer := httpsignatures.NewSigner("ed25519", "(request-target)", "host", "date")

		err := signer.SignRequest(r, ed25519TestPublicKey, ed25519TestPrivateKey)
		assert.Nil(t, err)

	}

	u, err := url.Parse("https://www.example.com/foo?param=value&pet=dog")
	assert.Nil(t, err)
	r := &http.Request{
		Header: http.Header{},
		Method: http.MethodGet,
		URL:    u,
	}

	editRequestFunc(r)

	_, err = httpsignatures.VerifyRequest(r, keyLookUpProp, -1, []string{httpsignatures.AlgorithmEd25519}, "(request-target)", "host", "date")
	assert.Nil(t, err)
}
