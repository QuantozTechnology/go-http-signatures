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

func TestHelpers(t *testing.T) {
	// test stripSignature
	sig := "Signature  OK"
	result := stripSignature(sig)
	if result != "OK" {
		t.Fatal("SplitSignature does not remove all whitespace")
	}
	sig = "Sigture  OK"
	result = stripSignature(sig)
	if result != "Sigture  OK" {
		t.Fatal("SplitSignature not correctly functioning")
	}

	// test splitSignature
	sig = "Signature keyId=\"Test\",algorithm=\"rsa-sha256\",signature=\"ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=\""

	sigArray := splitSignature(stripSignature(sig))
	sA1 := sigArray[0] == "keyId=\"Test\""
	sA2 := sigArray[1] == "algorithm=\"rsa-sha256\""
	sA3 := sigArray[2] == "signature=\"ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA=\""

	if (sA1 && sA2 && sA3) != true {
		t.Fatal("splitSignature has incorrect functionality")
	}

	if len(sigArray) != 3 {
		t.Fatal("splitSignature splitted extra data")
	}

	// test extractSignatureData
	sigDict := extractSignatureData(sigArray)
	sB1 := sigDict["keyId"] == "Test"
	sB2 := sigDict["algorithm"] == "rsa-sha256"
	sB3 := sigDict["signature"] == "ATp0r26dbMIxOopqw0OfABDT7CKMIoENumuruOtarj8n/97Q3htHFYpH8yOSQk3Z5zh8UxUym6FYTb5+A0Nz3NRsXJibnYi7brE/4tx5But9kkFGzG+xpUmimN4c3TMN7OFH//+r8hBf7BT9/GmHDUVZT2JzWGLZES2xDOUuMtA="
	
	if (sB1 && sB2 && sB3) != true {
		t.Fatal("extractData has incorrect functionality")
	}

	if len(sigDict) != 3 {
		t.Fatal("extractData parsed extra data")
	} 

}

