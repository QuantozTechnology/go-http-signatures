package httpsignatures

import (
	"net/http"
	"strings"
)

var (
	ErrorNoAlgorithmConfigured                     = "No algorithm configured"
	ErrorNoKeyIDConfigured                         = "No keyID configured"
	ErrorMissingRequiredHeader                     = "Missing required header"
	ErrorMissingSignatureParameterSignature        = "Missing signature parameter 'signature'"
	ErrorMissingSignatureParameterAlgorithm        = "Missing signature parameter 'algorithm'"
	ErrorMissingSignatureParameterKeyId            = "Missing signature parameter 'keyId'"
	ErrorNoSignatureHeaderFoundInRequest           = "No Signature header found in request"
	ErrorURLNotInRequest                           = "URL not in Request"
	ErrorMethodNotInRequest                        = "Method not in Request"
	ErrorSignaturesDoNotMatch                      = "Signatures do not match"
	ErrorAllowedClockskewExceeded                  = "Allowed clockskew exceeded"
	ErrorYouProbablyMisconfiguredAllowedClockSkew  = "You probably misconfigured allowedClockSkew, set to -1 to disable"
	ErrorRequiredHeaderNotInHeaderList             = "Required header not in header list"
	ErrorDateHeaderIsMissingForClockSkewComparison = "Date header is missing for clockSkew comparison"
	ErrorNoHeadersConfigLoaded                     = "No headers config loaded"
	ErrorAlgorithmNotAllowed                       = "The used encryption algorithm is not allowed"
)

func ErrorToHTTPCode(errString string) (int, string) {
	switch {
	case strings.HasPrefix(errString, ErrorNoAlgorithmConfigured):
		return http.StatusInternalServerError, ErrorNoAlgorithmConfigured
	case strings.HasPrefix(errString, ErrorNoKeyIDConfigured):
		return http.StatusInternalServerError, ErrorNoKeyIDConfigured
	case strings.HasPrefix(errString, ErrorNoHeadersConfigLoaded):
		return http.StatusInternalServerError, ErrorNoHeadersConfigLoaded
	case strings.HasPrefix(errString, ErrorYouProbablyMisconfiguredAllowedClockSkew):
		return http.StatusInternalServerError, ErrorYouProbablyMisconfiguredAllowedClockSkew
	case strings.HasPrefix(errString, ErrorMissingRequiredHeader):
		return http.StatusBadRequest, ErrorMissingRequiredHeader
	case strings.HasPrefix(errString, ErrorMissingSignatureParameterSignature):
		return http.StatusBadRequest, ErrorMissingSignatureParameterSignature
	case strings.HasPrefix(errString, ErrorMissingSignatureParameterAlgorithm):
		return http.StatusBadRequest, ErrorMissingSignatureParameterAlgorithm
	case strings.HasPrefix(errString, ErrorMissingSignatureParameterKeyId):
		return http.StatusBadRequest, ErrorMissingSignatureParameterKeyId
	case strings.HasPrefix(errString, ErrorNoSignatureHeaderFoundInRequest):
		return http.StatusBadRequest, ErrorNoSignatureHeaderFoundInRequest
	case strings.HasPrefix(errString, ErrorURLNotInRequest):
		return http.StatusBadRequest, ErrorURLNotInRequest
	case strings.HasPrefix(errString, ErrorMethodNotInRequest):
		return http.StatusBadRequest, ErrorMethodNotInRequest
	case strings.HasPrefix(errString, ErrorSignaturesDoNotMatch):
		return http.StatusBadRequest, ErrorSignaturesDoNotMatch
	case strings.HasPrefix(errString, ErrorAllowedClockskewExceeded):
		return http.StatusBadRequest, ErrorAllowedClockskewExceeded
	case strings.HasPrefix(errString, ErrorRequiredHeaderNotInHeaderList):
		return http.StatusBadRequest, ErrorRequiredHeaderNotInHeaderList
	case strings.HasPrefix(errString, ErrorDateHeaderIsMissingForClockSkewComparison):
		return http.StatusBadRequest, ErrorDateHeaderIsMissingForClockSkewComparison
	case strings.HasPrefix(errString, ErrorAlgorithmNotAllowed):
		return http.StatusBadRequest, ErrorAlgorithmNotAllowed
	default:
		return http.StatusInternalServerError, errString
	}
}
