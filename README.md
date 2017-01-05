httpsignatures-go
=================
[![GoDoc](https://godoc.org/github.com/QuantozTechnology/go-http-signatures?status.svg)](https://godoc.org/github.com/99designs/httpsignatures-go)
[![Build Status](https://travis-ci.org/QuantozTechnology/go-http-signatures.svg?branch=master)](https://travis-ci.org/QuantozTechnology/go-http-signatures)


Golang middleware library for the [http-signatures spec](https://tools.ietf.org/html/draft-cavage-http-signatures).

## Application
This is server side software, and can be used as middleware in for example the "goji" framework.

## Remarks
When the clockskew check is used, the X-Data header prevails over the Data header.

## Example
```go
import (
  "https://github.com/quantoztechnology/go-http-signatures"
)

var (
	ErrorIncorrectKeyIdSupplied = "Incorrect keyId supplied"
	ErrorNoAuthorization        = "Request not authorized"
)

// Authenticator checks if the request has the correct signature for authentication
func (app *App) Authenticator(c *web.C, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		err := verifyRequest(r)

		if err != nil {
			var httpErr int
			var msg string

			switch err.Error() {
			case ErrorIncorrectKeyIdSupplied:
				httpErr = http.StatusBadRequest
				msg = ErrorIncorrectKeyIdSupplied
			case ErrorNoAuthorization:
				httpErr = http.StatusUnauthorized
				msg = ErrorNoAuthorization
			default:
				httpErr, msg = httpsignatures.ErrorToHTTPCode(err.Error())
			}

			if httpErr == http.StatusInternalServerError {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			} else {
				http.Error(w, msg, httpErr)
				return
			}
		}

		h.ServeHTTP(w, r)
	})
}

func verifyRequest(r *http.Request) error {
	keyLookUp := func(keyId string) (string, error) {
		// returns the key to verify the signature
    return keyLookUpFun(keyId)
	}

	allowedClockSkew := -1
	requiredAlgorithm := []string{httpsignatures.AlgorithmHmacSha256}
	_, err := httpsignatures.VerifyRequest(r, keyLookUp, allowedClockSkew, requiredAlgorithm,
		httpsignatures.HeaderRequestTarget, httpsignatures.HeaderHost, httpsignatures.HeaderXDate)
	return err
}
```
