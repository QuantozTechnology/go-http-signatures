package httpsignatures

import (
    "net/http"
    "testing"
)

func TestSigAuthAuthenticate(t *testing.T) {
    r := &http.Request{Method: "GET"}

    authOpts := AuthOptions{
        Realm:  "Restricted",
    }

    b := &SigAuth{
        opts: authOpts,
    }

    if b.authenticate(nil) {
        t.Fatal("Should not succeed when http.Request is nil")
    }

	// Provide auth data, but no Authorization header
	if b.authenticate(r) != false {
		t.Fatal("No Authorization header supplied.")
	}

	// Initialise the map for HTTP headers
	r.Header = http.Header(make(map[string][]string))

	// Set a malformed/bad header
	r.Header.Set("Authorization", "    Signature")
	if b.authenticate(r) != false {
		t.Fatal("Malformed Authorization header supplied.")
	}

}