package httpsignatures

import (
	"net/http"
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
	switch errString {
	case ErrorNoAlgorithmConfigured:
		return http.StatusInternalServerError, ErrorNoAlgorithmConfigured
	case ErrorNoKeyIDConfigured:
		return http.StatusInternalServerError, ErrorNoKeyIDConfigured
	case ErrorNoHeadersConfigLoaded:
		return http.StatusInternalServerError, ErrorNoHeadersConfigLoaded
	case ErrorYouProbablyMisconfiguredAllowedClockSkew:
		return http.StatusInternalServerError, ErrorYouProbablyMisconfiguredAllowedClockSkew
	case ErrorMissingRequiredHeader:
		return http.StatusBadRequest, ErrorMissingRequiredHeader
	case ErrorMissingSignatureParameterSignature:
		return http.StatusBadRequest, ErrorMissingSignatureParameterSignature
	case ErrorMissingSignatureParameterAlgorithm:
		return http.StatusBadRequest, ErrorMissingSignatureParameterAlgorithm
	case ErrorMissingSignatureParameterKeyId:
		return http.StatusBadRequest, ErrorMissingSignatureParameterKeyId
	case ErrorNoSignatureHeaderFoundInRequest:
		return http.StatusBadRequest, ErrorNoSignatureHeaderFoundInRequest
	case ErrorURLNotInRequest:
		return http.StatusBadRequest, ErrorURLNotInRequest
	case ErrorMethodNotInRequest:
		return http.StatusBadRequest, ErrorMethodNotInRequest
	case ErrorSignaturesDoNotMatch:
		return http.StatusBadRequest, ErrorSignaturesDoNotMatch
	case ErrorAllowedClockskewExceeded:
		return http.StatusBadRequest, ErrorAllowedClockskewExceeded
	case ErrorRequiredHeaderNotInHeaderList:
		return http.StatusBadRequest, ErrorRequiredHeaderNotInHeaderList
	case ErrorDateHeaderIsMissingForClockSkewComparison:
		return http.StatusBadRequest, ErrorDateHeaderIsMissingForClockSkewComparison
	case ErrorAlgorithmNotAllowed:
		return http.StatusBadRequest, ErrorAlgorithmNotAllowed
	default:
		return http.StatusInternalServerError, "UnknownError"
	}
}
