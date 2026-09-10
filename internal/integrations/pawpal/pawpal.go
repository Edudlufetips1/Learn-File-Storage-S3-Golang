package pawpal

import (
	"crypto/subtle"
	"fmt"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey string, expectedKey string, payload any) WebhookVerification {
	if len(providedKey) != len(expectedKey) {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{Outcome: WebhookUnauthorized}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderIDVal, ok := payloadRecord["orderId"]
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	orderID, ok := orderIDVal.(float64)
	if !ok || orderID <= 0 || orderID != float64(int64(orderID)) {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	statusVal, ok := payloadRecord["status"]
	if !ok {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	statusStr, ok := statusVal.(string)
	if !ok || statusStr != "approved" {
		return WebhookVerification{Outcome: WebhookMalformed}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
