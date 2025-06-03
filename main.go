package main

import (
    "context"
    "crypto/rsa"
    "encoding/pem"
    "fmt"
    "log"
    "os"
    "strings"
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

    client := github.NewClient(nil).WithAuthToken(jwtToken)

    ctx := context.Background()
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

    total := 0
    protected := 0
    unprotected := 0

    fmt.Println("🔍 Repositories and branch protection status:
")

    for _, repo := range repos {
        fmt.Printf("📁 %s
", repo.GetName())
        total++

        branch := repo.GetDefaultBranch()
        p, _, err := client.Repositories.GetBranchProtection(ctx, org, repo.GetName(), branch)
        if err != nil {
            fmt.Println("Branch protection: not configured or insufficient permissions
")
            unprotected++
            continue
        }

        printProtectionSummary(p)
        fmt.Println()
        protected++
    }

    elapsed := time.Since(start).Seconds()
    fmt.Println("🔄 Summary")
    fmt.Printf("Repositories scanned: %d
", total)
    fmt.Printf("Protected branches found: %d
", protected)
    fmt.Printf("Unprotected or inaccessible branches: %d
", unprotected)
    fmt.Printf("Total time taken: %.2f seconds
", elapsed)
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

func printProtectionSummary(p *github.Protection) {
    if p == nil {
        fmt.Println("Branch protection: not configured")
        return
    }

    if p.RequiredPullRequestReviews != nil {
        r := p.RequiredPullRequestReviews
        fmt.Println("Require PR before merge:", boolToString(true))
        fmt.Println("Required number of approvals:", r.RequiredApprovingReviewCount)
        fmt.Println("Dismiss stale reviews:", boolToString(r.DismissStaleReviews))
        fmt.Println("Code owner reviews:", boolToString(r.RequireCodeOwnerReviews))

        if r.DismissalRestrictions != nil {
            fmt.Println("Restrict dismissals to users:", extractLogins(r.DismissalRestrictions.Users))
            fmt.Println("Restrict dismissals to teams:", extractSlugs(r.DismissalRestrictions.Teams))
        } else {
            fmt.Println("Restrict dismissals to users: not configured")
            fmt.Println("Restrict dismissals to teams: not configured")
        }

        if r.BypassPullRequestAllowances != nil {
            fmt.Println("Bypass PR requirements for users:", extractLogins(r.BypassPullRequestAllowances.Users))
            fmt.Println("Bypass PR requirements for teams:", extractSlugs(r.BypassPullRequestAllowances.Teams))
        }
    } else {
        fmt.Println("Require PR before merge: disabled")
    }

    if p.RequiredStatusChecks != nil {
        s := p.RequiredStatusChecks
        fmt.Println("Require status checks: enabled")
        fmt.Println("Status check strict mode:", boolToString(s.Strict))
        if len(s.Contexts) > 0 {
            fmt.Println("Status check contexts:", strings.Join(s.Contexts, ", "))
        } else {
            fmt.Println("Status check contexts: none configured")
        }
    } else {
        fmt.Println("Require status checks: disabled")
    }

    if p.EnforceAdmins != nil {
        fmt.Println("Enforce admins:", boolToString(p.EnforceAdmins.Enabled))
    } else {
        fmt.Println("Enforce admins: not configured")
    }

    if p.RequiredSignatures != nil && p.RequiredSignatures.Enabled != nil {
        fmt.Println("Require signed commits:", boolToString(*p.RequiredSignatures.Enabled))
    } else {
        fmt.Println("Require signed commits: not configured")
    }

    if p.RequiredConversationResolution != nil {
        fmt.Println("Require conversation resolution:", boolToString(p.RequiredConversationResolution.Enabled))
    } else {
        fmt.Println("Require conversation resolution: not configured")
    }

    if p.AllowForcePushes != nil {
        fmt.Println("Allow force pushes:", boolToString(p.AllowForcePushes.Enabled))
    } else {
        fmt.Println("Allow force pushes: not configured")
    }

    if p.AllowDeletions != nil {
        fmt.Println("Allow deletions:", boolToString(p.AllowDeletions.Enabled))
    } else {
        fmt.Println("Allow deletions: not configured")
    }
}

func boolToString(b bool) string {
    if b {
        return "enabled"
    }
    return "disabled"
}

func extractLogins(users []*github.User) string {
    if len(users) == 0 {
        return "none"
    }
    var list []string
    for _, u := range users {
        list = append(list, u.GetLogin())
    }
    return strings.Join(list, ", ")
}

func extractSlugs(teams []*github.Team) string {
    if len(teams) == 0 {
        return "none"
    }
    var list []string
    for _, t := range teams {
        list = append(list, t.GetSlug())
    }
    return strings.Join(list, ", ")
}
