package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
	"io/ioutil"
	"net/http"
)

// Step 1: Read required values from environment variables
var (
	appID          = os.Getenv("APP_ID")
	installationID = os.Getenv("INSTALLATION_ID")
	privateKeyPem  = os.Getenv("PRIVATE_KEY")
)

// getJWTToken generates a signed JWT to authenticate the GitHub App
func getJWTToken(appID string, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    appID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * 10)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(key)
}

// parsePrivateKey parses PEM-formatted private key text into rsa.PrivateKey
func parsePrivateKey(pemEncoded string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncoded))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemEncoded))
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	return key, nil
}

func main() {
	ctx := context.Background()

	// Step 2: Convert private key string to a usable format
	key, err := parsePrivateKey(privateKeyPem)
	if err != nil {
		log.Fatalf("❌ Error parsing private key: %v", err)
	}

	// Step 3: Generate JWT for GitHub App authentication
	jwtToken, err := getJWTToken(appID, key)
	if err != nil {
		log.Fatalf("❌ Error generating JWT: %v", err)
	}

	// Step 4: Get installation access token using JWT
	installationToken, err := getInstallationToken(ctx, jwtToken)
	if err != nil {
		log.Fatalf("❌ Error getting installation token: %v", err)
	}

	// Step 5: Use installation token to auth GitHub API client
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: installationToken})
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	// Step 6: List repositories in the org
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	org := "nanasec" // Replace with your GitHub org name

	fmt.Println("🔍 Repositories and branch protection status:")
	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			log.Fatalf("❌ Error listing repositories: %v", err)
		}

		for _, repo := range repos {
			fmt.Printf("\n📁 %s\n", repo.GetName())
			protection, _, err := client.Repositories.GetBranchProtection(ctx, org, repo.GetName(), repo.GetDefaultBranch())
			if err != nil {
				fmt.Println("⚠️  No branch protection or insufficient permissions")
				continue
			}
			printProtectionSummary(protection)
		}

		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
}

// getInstallationToken calls GitHub API to exchange JWT for installation token
func getInstallationToken(ctx context.Context, jwt string) (string, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%s/access_tokens", installationID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("GitHub API error: %s", string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return "", err
	}

	return result.Token, nil
}

// printProtectionSummary logs key protection settings for each repo
func printProtectionSummary(p *github.Protection) {
	fmt.Printf("🔐 Require PR reviews: %v\n", p.RequiredPullRequestReviews != nil)

	if p.EnforceAdmins != nil {
		fmt.Printf("🔒 Enforce admins: %v\n", p.EnforceAdmins.Enabled)
	} else {
		fmt.Println("🔒 Enforce admins: Not configured")
	}

	if p.RequiredStatusChecks != nil {
		fmt.Printf("✅ Required status checks: %v\n", p.RequiredStatusChecks.Contexts)
		fmt.Printf("🔁 Status checks must be up to date: %v\n", p.RequiredStatusChecks.Strict)
	} else {
		fmt.Println("✅ Required status checks: Not configured")
	}

	if p.RequiredSignatures != nil {
		fmt.Printf("🧱 Require signed commits: %v\n", *p.RequiredSignatures.Enabled)
	} else {
		fmt.Println("🧱 Require signed commits: Not configured")
	}

	// Linear history support is no longer directly available in this struct
	fmt.Println("🔄 Linear history: Not available in this API version")
}
