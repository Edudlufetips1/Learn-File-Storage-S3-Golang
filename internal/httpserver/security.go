package httpserver

import (
	"fmt"
	"net/http"
	"time"
)

func securityTxt(responseWriter http.ResponseWriter, request *http.Request) {
	expires := time.Now().UTC().Add(180 * 24 * time.Hour).Format(time.RFC3339)
	responseWriter.Header().Set("Content-Type", "text/plain")
	responseWriter.Header().Set("Expires", expires)
	fmt.Fprint(responseWriter, "Contact: mailto:security@bearlysecure.example\n")
	fmt.Fprint(responseWriter, "Policy: https://bearlysecure.example/security-policy\n")
	fmt.Fprint(responseWriter, "Expires: ", expires, "\n")
}
