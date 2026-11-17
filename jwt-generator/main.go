package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

type claims struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
}

func main() {
	username := flag.String("username", "mock-customer", "JWT username")
	role := flag.String("role", "Client User", "eZRx database role")
	ttl := flag.Duration("ttl", 10*time.Minute, "token lifetime")
	flag.Parse()

	if err := loadEnv(".env"); err != nil {
		fatal(err)
	}
	secret := os.Getenv("JWT_SECRET")
	if len(secret) != 36 {
		fatal(fmt.Errorf("JWT_SECRET must contain exactly 36 characters"))
	}
	if *ttl <= 0 {
		fatal(fmt.Errorf("ttl must be positive"))
	}

	now := time.Now()
	token, err := sign(secret, claims{
		ID:       1,
		Username: *username,
		Role:     *role,
		IssuedAt: now.Unix(),
		Expires:  now.Add(*ttl).Unix(),
		Issuer:   "Zuellig Pharma",
		Subject:  "Access Token",
	})
	if err != nil {
		fatal(err)
	}
	fmt.Printf("Bearer %s\n", token)
}

func sign(secret string, payload claims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(unsigned))
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func loadEnv(path string) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	for _, line := range strings.Split(string(contents), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) == "" {
			return fmt.Errorf("invalid .env entry %q", line)
		}
		if err := os.Setenv(strings.TrimSpace(key), strings.TrimSpace(value)); err != nil {
			return err
		}
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
