package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	expires, err := strconv.ParseInt(expiresValue, 10, 64)
	if err != nil || expires <= now.Unix() {
		return false
	}
	expectedSignature := signDownload(signingKey, fileID, expires)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func signDownload(signingKey [32]byte, fileID, expires int64) string {
	signedDownload := hmac.New(sha256.New, signingKey[:])
	fmt.Fprintf(signedDownload, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	return hex.EncodeToString(signedDownload.Sum(nil))
}
