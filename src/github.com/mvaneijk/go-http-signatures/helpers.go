package httpsignatures

import (
    "strings"
    "fmt"
)

// stripSignature trims the 'Signature' string from the
// Authorization string 
func stripSignature(sig string) string {
    if strings.HasPrefix(sig, "Signature ") {
        sub := strings.TrimLeft(sig, "Signature")
        return strings.TrimLeft(sub, " ")
    }
    return sig
}

// splitSignature splits the signature header on comma's
func splitSignature(sig string) []string {
    return strings.Split(sig, ",")
}

// extractSignatureData stores the data in a string map (dictionary)
func extractSignatureData(sig []string) map[string]string {
    data := map[string]string{}
    for _, s := range sig {
        fmt.Printf("s: %s", s)
        sub := strings.SplitN(s, "=", 2)
        trimmed := strings.Trim(sub[1], "\"")
        data[sub[0]] = trimmed
    }
    return data
}

// readSignature parses the Signature string and returns a
// dictionary with the data
func readSignature(sig string) map[string]string {
    return extractSignatureData(splitSignature(stripSignature(sig)))
}