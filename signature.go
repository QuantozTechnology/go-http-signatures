// httpsignatures is a golang implementation of the http-signatures spec
// found at https://tools.ietf.org/html/draft-cavage-http-signatures
package httpsignatures

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type SignatureParameters struct {
	KeyID      string
	Algorithm  *Algorithm
	Headers    HeaderValues
	HeaderList []string
	Signature  string
}

const (
	HeaderRequestTarget string = "(request-target)"
	HeaderDate          string = "date"
	HeaderXDate         string = "x-date"
	HeaderHost          string = "host"
)

// FromRequest takes the signature string from the HTTP-Request
// both Signature and Authorization http headers are supported.
func (s *SignatureParameters) FromRequest(r *http.Request) error {
	var httpSignatureString string
	if sig, ok := r.Header["Signature"]; ok {
		httpSignatureString = sig[0]
	} else {
		if h, ok := r.Header["Authorization"]; ok {
			httpSignatureString = strings.TrimPrefix(h[0], "Signature ")
		} else {
			return errors.New(ErrorNoSignatureHeaderFoundInRequest)
		}
	}
	if err := s.parseSignatureString(httpSignatureString); err != nil {
		return err
	}
	if err := s.ParseRequest(r); err != nil {
		return err
	}

	// todo: check if all required headers are available
	return nil
}

// FromConfig takes the string configuration and fills the
// SignatureParameters struct
func (s *SignatureParameters) FromConfig(keyId string, algorithm string, headers []string) error {
	if len(keyId) == 0 {
		return errors.New(ErrorNoKeyIDConfigured)
	}
	if len(algorithm) == 0 {
		return errors.New(ErrorNoAlgorithmConfigured)
	}
	s.KeyID = keyId

	alg, err := algorithmFromString(algorithm)
	if err != nil {
		return err
	}
	s.Algorithm = alg

	if len(headers) == 0 {
		s.HeaderList = []string{"date"}
		s.Headers = HeaderValues{}
	} else {
		s.Headers = HeaderValues{}
		for _, header := range headers {
			s.HeaderList = append(s.HeaderList, header)
		}
	}

	return nil
}

// ParseRequest extracts the header fields from the request required
// by the `headers` parameter in the configuration
func (s *SignatureParameters) ParseRequest(r *http.Request) error {
	if len(s.HeaderList) == 0 {
		return errors.New(ErrorNoHeadersConfigLoaded)
	}
	if len(s.HeaderList) > 0 {
		s.Headers = HeaderValues{}
	}
	for _, header := range s.HeaderList {
		switch header {
		case "(request-target)":
			if tl, err := requestTargetLine(r); err == nil {
				s.Headers[header] = strings.TrimSpace(tl)
			} else {
				return err
			}
		case "host":
			if host := r.Host; host != "" {
				s.Headers[header] = strings.TrimSpace(host)
			} else {
				return errors.New(ErrorMissingRequiredHeader + " 'host'")
			}
		default:
			// If there are multiple headers with the same name, add them all.
			if len(r.Header[http.CanonicalHeaderKey(header)]) > 0 {
				var trimmedValues []string
				for _, value := range r.Header[http.CanonicalHeaderKey(header)] {
					trimmedValues = append(trimmedValues, strings.TrimSpace(value))
				}
				s.Headers[header] = strings.Join(trimmedValues, ", ")
			} else {
				return fmt.Errorf("%s '%s'", ErrorMissingRequiredHeader, header)
			}
		}
	}
	return nil
}

// FromString creates a new Signature from its encoded form,
// eg `keyId="a",algorithm="b",headers="c",signature="d"`
func (s *SignatureParameters) parseSignatureString(in string) error {
	var key, value string
	*s = SignatureParameters{}
	signatureRegex := regexp.MustCompile(`(\w+)="([^"]*)"`)

	for _, m := range signatureRegex.FindAllStringSubmatch(in, -1) {
		key = m[1]
		value = m[2]

		if key == "keyId" {
			s.KeyID = value
		} else if key == "algorithm" {
			alg, err := algorithmFromString(value)
			if err != nil {
				return err
			}
			s.Algorithm = alg
		} else if key == "headers" {
			s.ParseString(value)
		} else if key == "signature" {
			s.Signature = value
		}
		// ignore unknown parameters
	}

	if len(s.HeaderList) == 0 {
		s.HeaderList = []string{"date"}
		s.Headers = HeaderValues{}
	}

	if len(s.Signature) == 0 {
		return errors.New(ErrorMissingSignatureParameterSignature)
	}

	if len(s.KeyID) == 0 {
		return errors.New(ErrorMissingSignatureParameterKeyId)
	}

	if s.Algorithm == nil {
		return errors.New(ErrorMissingSignatureParameterAlgorithm)
	}

	return nil
}

// String returns the encoded form of the Signature
func (s SignatureParameters) hTTPSignatureString(signature string) string {
	str := fmt.Sprintf(
		`keyId="%s",algorithm="%s"`,
		s.KeyID,
		s.Algorithm.Name,
	)

	if len(s.HeaderList) > 0 {
		str += fmt.Sprintf(`,headers="%s"`, s.toHeadersString())
	}

	str += fmt.Sprintf(`,signature="%s"`, signature)

	return str
}

func (s SignatureParameters) calculateSignature(keyB64 string) (string, error) {
	signingString, err := s.signingString()
	if err != nil {
		return "", err
	}
	byteKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return "", err
	}

	signature, err := s.Algorithm.Sign(&byteKey, []byte(signingString))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(*signature), err
}

// Verify verifies this signature for the given base64 encodedkey
func (s SignatureParameters) Verify(keyBase64 string) (bool, error) {
	signingString, err := s.signingString()
	if err != nil {
		return false, err
	}

	byteKey, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return false, err
	}

	byteSignature, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return false, err
	}

	result, err := s.Algorithm.Verify(&byteKey, []byte(signingString), &byteSignature)
	if err != nil {
		return false, err
	}

	return result, nil
}

// HeaderList contains headers
type HeaderValues map[string]string

// ParseString constructs a headerlist from the 'headers' string
func (s *SignatureParameters) ParseString(list string) {
	if len(list) == 0 {
		return
	}
	list = strings.TrimSpace(list)
	headers := strings.Split(strings.ToLower(string(list)), " ")
	for _, header := range headers {
		s.HeaderList = append(s.HeaderList, header)
	}
}

func (s SignatureParameters) toHeadersString() string {
	var lowerCaseList []string
	for _, header := range s.HeaderList {
		lowerCaseList = append(lowerCaseList, strings.ToLower(header))
	}

	return strings.Join(lowerCaseList, " ")
}

func (s SignatureParameters) signingString() (string, error) {
	signingList := []string{}

	for _, header := range s.HeaderList {
		headerString := fmt.Sprintf("%s: %s", header, s.Headers[header])
		signingList = append(signingList, headerString)
	}

	return strings.Join(signingList, "\n"), nil
}

func requestTargetLine(req *http.Request) (string, error) {
	if req.URL == nil {
		return "", errors.New(ErrorURLNotInRequest)
	}
	if len(req.Method) == 0 {
		return "", errors.New(ErrorMethodNotInRequest)
	}

	path := req.URL.Path
	var query, fragment string
	if q := req.URL.RawQuery; len(q) != 0 {
		query = "?" + q
	}
	if f := req.URL.Fragment; len(f) != 0 {
		fragment = "#" + f
	}
	method := strings.ToLower(req.Method)
	return fmt.Sprintf("%s %s%s%s", method, path, query, fragment), nil
}

func headerLine(req *http.Request, header string) (string, error) {
	if value := req.Header.Get(header); value != "" {
		return fmt.Sprintf("%s: %s", header, value), nil
	}
	return "", fmt.Errorf("%s '%s'", ErrorMissingRequiredHeader, header)
}
