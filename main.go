package main

import (
	"context"
	"crypto/rsa"
	"encoding/csv"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
)

// BranchProtectionReport represents a comprehensive branch protection report
type BranchProtectionReport struct {
	Repository                               string
	Branch                                   string
	RequirePullRequestBeforeMerging         string
	RequireApprovals                        string
	RequiredNumberOfApprovals               string
	DismissStaleReviews                     string
	RequireCodeOwnerReviews                 string
	RestrictWhoCanDismissReviews            string
	TeamsOrAppsCanDismissReviews            string
	BypassAllowanceUsers                    string
	BypassAllowanceTeams                    string
	RequireApprovalOfMostRecentPush         string
	RequiredStatusChecks                    string
	StatusChecksStrict                      string
	RequiredConversationResolution          string
	RequireSignedCommits                    string
	RequireLinearHistory                    string
	AllowForkSyncing                        string
	LockBranch                              string
	EnforceAdmins                           string
	RestrictPushes                          string
	UserPushRestrictions                    string
	TeamPushRestrictions                    string
	AllowForcePushes                        string
	AllowDeletions                          string
}

func main() {
	start := time.Now()

	appID := os.Getenv("APP_ID")
	installationID := os.Getenv("INSTALLATION_ID")
	privateKeyPEM := os.Getenv("PRIVATE_KEY")
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		org = "nanasec" // default org
	}

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

	repos, _, err := client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		log.Fatalf("Failed to list repositories: %v", err)
	}

	total := len(repos)
	fmt.Printf("Found %d repositories. Starting scan...\n", total)

	csvFile, err := os.Create("comprehensive_branch_protection_report.csv")
	if err != nil {
		log.Fatalf("Could not create CSV file: %v", err)
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write comprehensive headers
	headers := []string{
		"Repository", "Branch",
		"Require a Pull Request Before Merging",
		"Require Approvals",
		"Required Number of Approvals",
		"Dismiss Stale Pull Request Approvals",
		"Require Review from Code Owners",
		"Restrict Who Can Dismiss Pull Request Reviews",
		"Teams, or Apps that Can Dismiss Reviews",
		"Bypass Allowance Users",
		"Bypass Allowance Teams",
		"Require Approval of the Most Recent Push",
		"Required Status Checks",
		"Status Checks Strict",
		"Required Conversation Resolution",
		"Require Signed Commits",
		"Require Linear History",
		"Allow Fork Syncing",
		"Lock Branch",
		"Enforce Admins",
		"Restrict pushes",
		"User Push Restrictions",
		"Team Push Restrictions",
		"Allow Force Pushes",
		"Allow Deletions",
	}
	
	if err := writer.Write(headers); err != nil {
		log.Fatalf("Failed to write CSV headers: %v", err)
	}

	// Process repositories concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent requests
	mu := sync.Mutex{}
	
	protected, unprotected := 0, 0

	for _, repo := range repos {
		wg.Add(1)
		go func(repo *github.Repository) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release

			report := processRepository(ctx, client, org, repo)
			
			mu.Lock()
			defer mu.Unlock()
			
			if report != nil {
				if err := writer.Write(reportToSlice(report)); err != nil {
					log.Printf("Failed to write report for %s: %v", repo.GetName(), err)
				} else {
					if report.RequirePullRequestBeforeMerging != "No" {
						protected++
					} else {
						unprotected++
					}
				}
			} else {
				unprotected++
			}
		}(repo)
	}

	wg.Wait()

	elapsed := time.Since(start).Seconds()
	fmt.Println("\nScan complete.")
	fmt.Printf("Repositories scanned: %d\n", total)
	fmt.Printf("Protected branches found: %d\n", protected)
	fmt.Printf("Unprotected or inaccessible branches: %d\n", unprotected)
	fmt.Printf("Total time taken: %.2f seconds\n", elapsed)
	fmt.Println("Comprehensive CSV report saved as comprehensive_branch_protection_report.csv")
}

func processRepository(ctx context.Context, client *github.Client, org string, repo *github.Repository) *BranchProtectionReport {
	repoName := repo.GetName()
	defaultBranch := repo.GetDefaultBranch()
	
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	fmt.Printf("Processing: %s/%s (branch: %s)\n", org, repoName, defaultBranch)

	protection, resp, err := client.Repositories.GetBranchProtection(ctx, org, repoName, defaultBranch)
	if err != nil {
		// Check if it's a 404 (no protection) vs other errors
		if resp != nil && resp.StatusCode == 404 {
			// No protection configured
			return &BranchProtectionReport{
				Repository:                      repoName,
				Branch:                         defaultBranch,
				RequirePullRequestBeforeMerging: "No",
				RequireApprovals:               "No",
				RequiredNumberOfApprovals:      "0",
				DismissStaleReviews:            "No",
				RequireCodeOwnerReviews:        "No",
				RestrictWhoCanDismissReviews:   "None configured",
				TeamsOrAppsCanDismissReviews:   "None configured",
				BypassAllowanceUsers:           "None configured",
				BypassAllowanceTeams:           "None configured",
				RequireApprovalOfMostRecentPush: "No",
				RequiredStatusChecks:           "None configured",
				StatusChecksStrict:             "No",
				RequiredConversationResolution: "No",
				RequireSignedCommits:           "No",
				RequireLinearHistory:           "No",
				AllowForkSyncing:              "No",
				LockBranch:                    "No",
				EnforceAdmins:                 "No",
				RestrictPushes:                "No",
				UserPushRestrictions:          "None configured",
				TeamPushRestrictions:          "None configured",
				AllowForcePushes:              "No",
				AllowDeletions:                "No",
			}
		}
		log.Printf("Failed to get protection for %s/%s: %v", org, repoName, err)
		return nil
	}

	return parseProtectionToReport(repoName, defaultBranch, protection)
}

func parseProtectionToReport(repoName, branch string, protection *github.Protection) *BranchProtectionReport {
	report := &BranchProtectionReport{
		Repository: repoName,
		Branch:    branch,
	}

	// Pull Request Reviews
	if protection.RequiredPullRequestReviews != nil {
		prReviews := protection.RequiredPullRequestReviews
		
		report.RequirePullRequestBeforeMerging = "Yes"
		report.RequireApprovals = boolToYesNo(prReviews.RequiredApprovingReviewCount > 0)
		report.RequiredNumberOfApprovals = strconv.Itoa(prReviews.RequiredApprovingReviewCount)
		report.DismissStaleReviews = boolToYesNo(prReviews.DismissStaleReviews)
		report.RequireCodeOwnerReviews = boolToYesNo(prReviews.RequireCodeOwnerReviews)
		report.RequireApprovalOfMostRecentPush = boolToYesNo(prReviews.RequireLastPushApproval)

		// Dismissal restrictions
		if prReviews.DismissalRestrictions != nil {
			report.RestrictWhoCanDismissReviews = formatUsers(prReviews.DismissalRestrictions.Users)
			report.TeamsOrAppsCanDismissReviews = formatTeams(prReviews.DismissalRestrictions.Teams)
		} else {
			report.RestrictWhoCanDismissReviews = "None configured"
			report.TeamsOrAppsCanDismissReviews = "None configured"
		}

		// Bypass allowances
		if prReviews.BypassPullRequestAllowances != nil {
			report.BypassAllowanceUsers = formatUsers(prReviews.BypassPullRequestAllowances.Users)
			report.BypassAllowanceTeams = formatTeams(prReviews.BypassPullRequestAllowances.Teams)
		} else {
			report.BypassAllowanceUsers = "None configured"
			report.BypassAllowanceTeams = "None configured"
		}
	} else {
		report.RequirePullRequestBeforeMerging = "No"
		report.RequireApprovals = "No"
		report.RequiredNumberOfApprovals = "0"
		report.DismissStaleReviews = "No"
		report.RequireCodeOwnerReviews = "No"
		report.RequireApprovalOfMostRecentPush = "No"
		report.RestrictWhoCanDismissReviews = "None configured"
		report.TeamsOrAppsCanDismissReviews = "None configured"
		report.BypassAllowanceUsers = "None configured"
		report.BypassAllowanceTeams = "None configured"
	}

	// Status Checks
	if protection.RequiredStatusChecks != nil {
		statusChecks := protection.RequiredStatusChecks
		if len(statusChecks.Contexts) > 0 {
			report.RequiredStatusChecks = strings.Join(statusChecks.Contexts, ", ")
		} else {
			report.RequiredStatusChecks = "None configured"
		}
		report.StatusChecksStrict = boolToYesNo(statusChecks.Strict)
	} else {
		report.RequiredStatusChecks = "None configured"
		report.StatusChecksStrict = "No"
	}

	// Enforce Admins
	if protection.EnforceAdmins != nil {
		report.EnforceAdmins = boolToYesNo(protection.EnforceAdmins.Enabled)
	} else {
		report.EnforceAdmins = "No"
	}

	// Signed Commits
	if protection.RequiredSignatures != nil && protection.RequiredSignatures.Enabled != nil {
		report.RequireSignedCommits = boolToYesNo(*protection.RequiredSignatures.Enabled)
	} else {
		report.RequireSignedCommits = "No"
	}

	// Linear History (Note: This field may not be available in all GitHub API versions)
	// Setting to "No" as this field is not consistently available in the go-github library
	report.RequireLinearHistory = "No"

	// Allow Fork Syncing
	if protection.AllowForkSyncing != nil && protection.AllowForkSyncing.Enabled != nil {
		report.AllowForkSyncing = boolToYesNo(*protection.AllowForkSyncing.Enabled)
	} else {
		report.AllowForkSyncing = "No"
	}

	// Lock Branch
	if protection.LockBranch != nil && protection.LockBranch.Enabled != nil {
		report.LockBranch = boolToYesNo(*protection.LockBranch.Enabled)
	} else {
		report.LockBranch = "No"
	}

	// Block Creations (Restrict pushes)
	if protection.BlockCreations != nil && protection.BlockCreations.Enabled != nil {
		report.RestrictPushes = boolToYesNo(*protection.BlockCreations.Enabled)
	} else {
		report.RestrictPushes = "No"
	}

	// Push Restrictions
	if protection.Restrictions != nil {
		report.UserPushRestrictions = formatUsers(protection.Restrictions.Users)
		report.TeamPushRestrictions = formatTeams(protection.Restrictions.Teams)
	} else {
		report.UserPushRestrictions = "None configured"
		report.TeamPushRestrictions = "None configured"
	}

	// Force Pushes
	if protection.AllowForcePushes != nil && protection.AllowForcePushes.Enabled != nil {
		report.AllowForcePushes = boolToYesNo(*protection.AllowForcePushes.Enabled)
	} else {
		report.AllowForcePushes = "No"
	}

	// Deletions
	if protection.AllowDeletions != nil && protection.AllowDeletions.Enabled != nil {
		report.AllowDeletions = boolToYesNo(*protection.AllowDeletions.Enabled)
	} else {
		report.AllowDeletions = "No"
	}

	// Conversation Resolution
	if protection.RequiredConversationResolution != nil && protection.RequiredConversationResolution.Enabled != nil {
		report.RequiredConversationResolution = boolToYesNo(*protection.RequiredConversationResolution.Enabled)
	} else {
		report.RequiredConversationResolution = "No"
	}

	return report
}

func reportToSlice(report *BranchProtectionReport) []string {
	return []string{
		report.Repository,
		report.Branch,
		report.RequirePullRequestBeforeMerging,
		report.RequireApprovals,
		report.RequiredNumberOfApprovals,
		report.DismissStaleReviews,
		report.RequireCodeOwnerReviews,
		report.RestrictWhoCanDismissReviews,
		report.TeamsOrAppsCanDismissReviews,
		report.BypassAllowanceUsers,
		report.BypassAllowanceTeams,
		report.RequireApprovalOfMostRecentPush,
		report.RequiredStatusChecks,
		report.StatusChecksStrict,
		report.RequiredConversationResolution,
		report.RequireSignedCommits,
		report.RequireLinearHistory,
		report.AllowForkSyncing,
		report.LockBranch,
		report.EnforceAdmins,
		report.RestrictPushes,
		report.UserPushRestrictions,
		report.TeamPushRestrictions,
		report.AllowForcePushes,
		report.AllowDeletions,
	}
}

func formatUsers(users []*github.User) string {
	if len(users) == 0 {
		return "None configured"
	}
	usernames := make([]string, len(users))
	for i, user := range users {
		usernames[i] = user.GetLogin()
	}
	return strings.Join(usernames, ", ")
}

func formatTeams(teams []*github.Team) string {
	if len(teams) == 0 {
		return "None configured"
	}
	teamNames := make([]string, len(teams))
	for i, team := range teams {
		teamNames[i] = team.GetSlug()
	}
	return strings.Join(teamNames, ", ")
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

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
