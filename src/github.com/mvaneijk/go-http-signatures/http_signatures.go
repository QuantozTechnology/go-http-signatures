package httpsignatures

import (
	"fmt"
	"net/http"
)

type SigAuth struct {
	h    http.Handler
	opts AuthOptions
}

// AuthOptions stores the configuration for Authentication.
//
// A http.Handler may also be passed to UnauthorizedHandler to override the
// default error handler if you wish to serve a custom template/response.
type AuthOptions struct {
	Realm               string
	// Algorithm           string
	UnauthorizedHandler http.Handler
}

// Satisfies the http.Handler interface for basicAuth.
func (s SigAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if we have a user-provided error handler, else set a default
	if s.opts.UnauthorizedHandler == nil {
		s.opts.UnauthorizedHandler = http.HandlerFunc(defaultUnauthorizedHandler)
	}

	// Check that the provided details match
	if s.authenticate(r) == false {
		s.requestAuth(w, r)
		return
	}

	// Call the next handler on success.
	s.h.ServeHTTP(w, r)
}

// authenticate checks the signature provided in the request header.
// Returns 'false' if the user has not successfully authenticated.
func (s *SigAuth) authenticate(r *http.Request) bool {
    return false
}

// Require authentication, and serve our error handler otherwise.
func (s *SigAuth) requestAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Authorization realm=%q`, s.opts.Realm))
	s.opts.UnauthorizedHandler.ServeHTTP(w, r)
}

// defaultUnauthorizedHandler provides a default HTTP 401 Unauthorized response.
func defaultUnauthorizedHandler(w http.ResponseWriter, r *http.Request) {
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}