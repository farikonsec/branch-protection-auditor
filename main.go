package main

import (
    "context"
    "crypto/rsa"
    "encoding/csv"
    "encoding/pem"
    "fmt"
    "log"
    "os"
    "time"
    "github.com/golang-jwt/jwt/v5"
    "github.com/google/go-github/v53/github"
    "golang.org/x/oauth2"
)

func main() {
    start := time.Now()

    appID := os.Getenv("APP_ID")
    installationID := os.Getenv("INSTALLATION_ID")
    privateKeyPEM := os.Getenv("PRIVATE_KEY")
    org := "nanasec"

    if appID == "" || installationID == "" || privateKeyPEM == "" {
        log.Fatal("Missing APP_ID, INSTALLATION_ID, or PRIVATE_KEY environment variables")
    }

    key, err := parsePrivateKey(privateKeyPEM)
    if err != nil {
        log.Fatalf("Failed to parse private key: %v", err)
    }

    jwtToken, err := generateJWT(appID, key)
    if err != nil {
        log.Fatalf("Failed to generate JWT: %v", err)
    }

    ctx := context.Background()
    jwtTokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken})
    jwtClient := oauth2.NewClient(ctx, jwtTokenSource)
    client := github.NewClient(jwtClient)

    token, _, err := client.Apps.CreateInstallationToken(ctx, parseInt64(installationID), nil)
    if err != nil {
        log.Fatalf("Failed to create installation token: %v", err)
    }

    ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.GetToken()})
    tc := oauth2.NewClient(ctx, ts)
    client = github.NewClient(tc)

    repos, _, err := client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{Type: "all"})
    if err != nil {
        log.Fatalf("Failed to list repositories: %v", err)
    }

    total, protected, unprotected := 0, 0, 0
    fmt.Println("Scanning repositories...")

    csvFile, err := os.Create("branch_protection_report.csv")
    if err != nil {
        log.Fatalf("Could not create CSV file: %v", err)
    }
    defer csvFile.Close()
    writer := csv.NewWriter(csvFile)
    defer writer.Flush()

    headers := []string{"Repository", "RequirePR", "Approvals", "DismissStale", "CodeOwnerReviews", "EnforceAdmins", "SignedCommits", "ConversationResolution", "StatusChecks", "StrictStatus", "ForcePushes", "Deletions"}
    writer.Write(headers)

    for _, repo := range repos {
        total++
        branch := repo.GetDefaultBranch()
        p, _, err := client.Repositories.GetBranchProtection(ctx, org, repo.GetName(), branch)
        if err != nil {
            unprotected++
            continue
        }

        record := []string{repo.GetName()}

        if p.RequiredPullRequestReviews != nil {
            r := p.RequiredPullRequestReviews
            record = append(record,
                "enabled",
                fmt.Sprintf("%d", r.RequiredApprovingReviewCount),
                boolToString(r.DismissStaleReviews),
                boolToString(r.RequireCodeOwnerReviews),
            )
        } else {
            record = append(record, "disabled", "0", "disabled", "disabled")
        }

        if p.EnforceAdmins != nil {
            record = append(record, boolToString(p.EnforceAdmins.Enabled))
        } else {
            record = append(record, "not configured")
        }

        if p.RequiredSignatures != nil && p.RequiredSignatures.Enabled != nil {
            record = append(record, boolToString(*p.RequiredSignatures.Enabled))
        } else {
            record = append(record, "not configured")
        }

        if p.RequiredConversationResolution != nil {
            record = append(record, boolToString(p.RequiredConversationResolution.Enabled))
        } else {
            record = append(record, "not configured")
        }

        if p.RequiredStatusChecks != nil {
            s := p.RequiredStatusChecks
            record = append(record, "enabled", boolToString(s.Strict))
        } else {
            record = append(record, "disabled", "disabled")
        }

        if p.AllowForcePushes != nil {
            record = append(record, boolToString(p.AllowForcePushes.Enabled))
        } else {
            record = append(record, "not configured")
        }

        if p.AllowDeletions != nil {
            record = append(record, boolToString(p.AllowDeletions.Enabled))
        } else {
            record = append(record, "not configured")
        }

        writer.Write(record)
        protected++
    }

    elapsed := time.Since(start).Seconds()
    fmt.Println("Scan complete.")
    fmt.Printf("Repositories scanned: %d\n", total)
    fmt.Printf("Protected branches found: %d\n", protected)
    fmt.Printf("Unprotected or inaccessible branches: %d\n", unprotected)
    fmt.Printf("Total time taken: %.2f seconds\n", elapsed)
    fmt.Println("CSV report saved as branch_protection_report.csv")
}

func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(pemStr))
    if block == nil {
        return nil, fmt.Errorf("failed to decode PEM block")
    }
    return jwt.ParseRSAPrivateKeyFromPEM([]byte(pemStr))
}

func generateJWT(appID string, key *rsa.PrivateKey) (string, error) {
    now := time.Now()
    claims := jwt.RegisteredClaims{
        IssuedAt:  jwt.NewNumericDate(now),
        ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute * 10)),
        Issuer:    appID,
    }
    token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
    return token.SignedString(key)
}

func parseInt64(s string) int64 {
    var id int64
    fmt.Sscanf(s, "%d", &id)
    return id
}

func boolToString(b bool) string {
    if b {
        return "enabled"
    }
    return "disabled"
}
