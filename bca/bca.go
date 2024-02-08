package bca

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
)

type BCA struct {
	URL string

	clientSecret string
	clientID     string
}

type AccessToken string

type Signature string

func (b *BCA) OAuth(ctx context.Context) (AccessToken, error) {
	auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", b.clientID, b.clientSecret)))
	contentType := "application/x-www-form-urlencoded"
	grantType := "client_credentials"
	url := fmt.Sprintf("%s/api/oauth/token", b.URL)

	// body preparation
	body, err := json.Marshal(struct {
		GrantType string `json:"grant_type"`
	}{
		GrantType: grantType,
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal json: %w", err)
	}

	// http call
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to create new request: %w", err)
	}

	req.Header.Add("Authorization", auth)
	req.Header.Add("Content-Type", contentType)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call http request: %w", err)
	}
	defer resp.Body.Close()

	// read body
	data := struct {
		AccessToken string `json:"access_token"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return "", err
	}

	return AccessToken(data.AccessToken), nil
}

// generateSignature is to SHA-256 HMAC is used to generate the signature with your API secret as the key.
// Signature = HMAC-SHA256(apiSecret, StringToSign)
// StringToSign = HTTPMethod+":"+RelativeUrl+":"+AccessToken+":"+Lowercase(HexEncode(SHA-256(RequestBody)))+":"+Timestamp
// For GET request (with no RequestBody), you still need to calculate SHA-256 of an empty string.
func (b *BCA) generateSignature(httpMethod, relativeURL, accessToken, reqBody, timestamp string) (Signature, error) {
	return "", nil
}

func NewBCA(URL, clientID, clientSecret string) BCA {
	return BCA{
		URL:          URL,
		clientSecret: clientSecret,
		clientID:     clientID,
	}
}
