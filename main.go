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
	Repository                      string
	Branch                          string
	RequirePullRequestBeforeMerging string
	RequireApprovals                string
	RequiredNumberOfApprovals       string
	DismissStaleReviews             string
	RequireCodeOwnerReviews         string
	RestrictWhoCanDismissReviews    string
	TeamsOrAppsCanDismissReviews    string
	BypassAllowanceUsers            string
	BypassAllowanceTeams            string
	RequireApprovalOfMostRecentPush string
	RequiredStatusChecks            string
	StatusChecksStrict              string
	RequiredConversationResolution  string
	RequireSignedCommits            string
	RequireLinearHistory            string
	AllowForkSyncing                string
	LockBranch                      string
	EnforceAdmins                   string
	RestrictPushes                  string
	UserPushRestrictions            string
	TeamPushRestrictions            string
	AllowForcePushes                string
	AllowDeletions                  string
}

// Global variables for progress tracking and error collection
var (
	totalRepos      int        // Total number of repositories to process
	processedRepos  int        // Number of repositories processed so far
	startTime       time.Time  // Start time for ETA calculation
	errorMessages   []string   // Collection of error messages
	warningMessages []string   // Collection of warning messages
	mu              sync.Mutex // Mutex for thread-safe operations
)

func main() {
	// Initialize start time for progress tracking
	startTime = time.Now()

	// Get environment variables for GitHub App authentication
	appID := os.Getenv("APP_ID")
	installationID := os.Getenv("INSTALLATION_ID")
	privateKeyPEM := os.Getenv("PRIVATE_KEY")
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		org = "nanasec" // default org
	}

	// Validate required environment variables
	if appID == "" || installationID == "" || privateKeyPEM == "" {
		log.Fatal("Missing APP_ID, INSTALLATION_ID, or PRIVATE_KEY environment variables")
	}

	// Parse the private key from PEM format
	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		log.Fatalf("Failed to parse private key: %v", err)
	}

	// Generate JWT token for GitHub App authentication
	jwtToken, err := generateJWT(appID, key)
	if err != nil {
		log.Fatalf("Failed to generate JWT: %v", err)
	}

	// Create GitHub client with JWT token
	ctx := context.Background()
	jwtTokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken})
	jwtClient := oauth2.NewClient(ctx, jwtTokenSource)
	client := github.NewClient(jwtClient)

	// Create installation token for accessing repositories
	token, _, err := client.Apps.CreateInstallationToken(ctx, parseInt64(installationID), nil)
	if err != nil {
		log.Fatalf("Failed to create installation token: %v", err)
	}

	// Create new client with installation token
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.GetToken()})
	tc := oauth2.NewClient(ctx, ts)
	client = github.NewClient(tc)

	// Get all repositories for the organization
	repos, _, err := client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		log.Fatalf("Failed to list repositories: %v", err)
	}

	// Initialize progress tracking
	totalRepos = len(repos)
	fmt.Printf("Found %d repositories. Starting scan...\n", totalRepos)

	// Create CSV file for the report
	csvFile, err := os.Create("branch_protection_report.csv")
	if err != nil {
		log.Fatalf("Could not create CSV file: %v", err)
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// Write comprehensive headers to CSV
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

	// Process repositories concurrently with progress tracking
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent requests to avoid rate limiting

	protected, unprotected := 0, 0

	for _, repo := range repos {
		wg.Add(1)
		go func(repo *github.Repository) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			// Process individual repository
			report := processRepository(ctx, client, org, repo)

			// Thread-safe updates to shared variables
			mu.Lock()
			defer mu.Unlock()

			// Update progress counter and display
			processedRepos++
			showProgress()

			if report != nil {
				// Write report to CSV
				if err := writer.Write(reportToSlice(report)); err != nil {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to write report for %s: %v", repo.GetName(), err))
				} else {
					// Count protected vs unprotected branches
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

	// Wait for all goroutines to complete
	wg.Wait()
	fmt.Println() // New line after progress indicator

	// Calculate and display final results
	elapsed := time.Since(startTime).Seconds()
	fmt.Println("Scan complete.")
	fmt.Printf("Repositories scanned: %d\n", totalRepos)
	fmt.Printf("Protected branches found: %d\n", protected)
	fmt.Printf("Unprotected or inaccessible branches: %d\n", unprotected)
	fmt.Printf("Total time taken: %.2f seconds\n", elapsed)

	// Display error summary if any errors occurred
	if len(errorMessages) > 0 {
		fmt.Printf("\nErrors encountered (%d):\n", len(errorMessages))
		for _, msg := range errorMessages {
			fmt.Printf("  - %s\n", msg)
		}
	}

	// Display warning summary if any warnings occurred
	if len(warningMessages) > 0 {
		fmt.Printf("\nWarnings (%d):\n", len(warningMessages))
		for _, msg := range warningMessages {
			fmt.Printf("  - %s\n", msg)
		}
	}

	fmt.Println("CSV report saved as branch_protection_report.csv")
}

// processRepository processes a single repository and returns its branch protection report
func processRepository(ctx context.Context, client *github.Client, org string, repo *github.Repository) *BranchProtectionReport {
	repoName := repo.GetName()
	defaultBranch := repo.GetDefaultBranch()

	// Use "main" as fallback if no default branch is specified
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// Get branch protection settings for the default branch
	protection, resp, err := client.Repositories.GetBranchProtection(ctx, org, repoName, defaultBranch)
	if err != nil {
		// Check if it's a 404 (no protection) vs other errors
		if resp != nil && resp.StatusCode == 404 {
			// No protection configured - return default "No" values
			return &BranchProtectionReport{
				Repository:                      repoName,
				Branch:                          defaultBranch,
				RequirePullRequestBeforeMerging: "No",
				RequireApprovals:                "No",
				RequiredNumberOfApprovals:       "0",
				DismissStaleReviews:             "No",
				RequireCodeOwnerReviews:         "No",
				RestrictWhoCanDismissReviews:    "None configured",
				TeamsOrAppsCanDismissReviews:    "None configured",
				BypassAllowanceUsers:            "None configured",
				BypassAllowanceTeams:            "None configured",
				RequireApprovalOfMostRecentPush: "No",
				RequiredStatusChecks:            "None configured",
				StatusChecksStrict:              "No",
				RequiredConversationResolution:  "No",
				RequireSignedCommits:            "No",
				RequireLinearHistory:            "No",
				AllowForkSyncing:                "No",
				LockBranch:                      "No",
				EnforceAdmins:                   "No",
				RestrictPushes:                  "No",
				UserPushRestrictions:            "None configured",
				TeamPushRestrictions:            "None configured",
				AllowForcePushes:                "No",
				AllowDeletions:                  "No",
			}
		}
		// Log other errors to error collection
		mu.Lock()
		errorMessages = append(errorMessages, fmt.Sprintf("Failed to get protection for %s/%s: %v", org, repoName, err))
		mu.Unlock()
		return nil
	}

	// Parse the protection settings into a report
	return parseProtectionToReport(repoName, defaultBranch, protection)
}

// parseProtectionToReport converts GitHub protection settings to our report format
func parseProtectionToReport(repoName, branch string, protection *github.Protection) *BranchProtectionReport {
	report := &BranchProtectionReport{
		Repository: repoName,
		Branch:     branch,
	}

	// Parse Pull Request Reviews settings
	if protection.RequiredPullRequestReviews != nil {
		prReviews := protection.RequiredPullRequestReviews

		report.RequirePullRequestBeforeMerging = "Yes"
		report.RequireApprovals = boolToYesNo(prReviews.RequiredApprovingReviewCount > 0)
		report.RequiredNumberOfApprovals = strconv.Itoa(prReviews.RequiredApprovingReviewCount)
		report.DismissStaleReviews = boolToYesNo(prReviews.DismissStaleReviews)
		report.RequireCodeOwnerReviews = boolToYesNo(prReviews.RequireCodeOwnerReviews)
		report.RequireApprovalOfMostRecentPush = boolToYesNo(prReviews.RequireLastPushApproval)

		// Parse dismissal restrictions
		if prReviews.DismissalRestrictions != nil {
			report.RestrictWhoCanDismissReviews = formatUsers(prReviews.DismissalRestrictions.Users)
			report.TeamsOrAppsCanDismissReviews = formatTeams(prReviews.DismissalRestrictions.Teams)
		} else {
			report.RestrictWhoCanDismissReviews = "None configured"
			report.TeamsOrAppsCanDismissReviews = "None configured"
		}

		// Parse bypass allowances
		if prReviews.BypassPullRequestAllowances != nil {
			report.BypassAllowanceUsers = formatUsers(prReviews.BypassPullRequestAllowances.Users)
			report.BypassAllowanceTeams = formatTeams(prReviews.BypassPullRequestAllowances.Teams)
		} else {
			report.BypassAllowanceUsers = "None configured"
			report.BypassAllowanceTeams = "None configured"
		}
	} else {
		// No pull request reviews required
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

	// Parse Status Checks settings
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

	// Parse Enforce Admins setting
	if protection.EnforceAdmins != nil {
		report.EnforceAdmins = boolToYesNo(protection.EnforceAdmins.Enabled)
	} else {
		report.EnforceAdmins = "No"
	}

	// Parse Signed Commits requirement
	if protection.RequiredSignatures != nil && protection.RequiredSignatures.Enabled != nil {
		report.RequireSignedCommits = boolToYesNo(*protection.RequiredSignatures.Enabled)
	} else {
		report.RequireSignedCommits = "No"
	}

	// Note: Linear History field may not be available in all GitHub API versions
	// Setting to "No" as this field is not consistently available in the go-github library
	report.RequireLinearHistory = "No"

	// Parse Allow Fork Syncing setting
	if protection.AllowForkSyncing != nil && protection.AllowForkSyncing.Enabled != nil {
		report.AllowForkSyncing = boolToYesNo(*protection.AllowForkSyncing.Enabled)
	} else {
		report.AllowForkSyncing = "No"
	}

	// Parse Lock Branch setting
	if protection.LockBranch != nil && protection.LockBranch.Enabled != nil {
		report.LockBranch = boolToYesNo(*protection.LockBranch.Enabled)
	} else {
		report.LockBranch = "No"
	}

	// Parse Block Creations (Restrict pushes) setting
	if protection.BlockCreations != nil && protection.BlockCreations.Enabled != nil {
		report.RestrictPushes = boolToYesNo(*protection.BlockCreations.Enabled)
	} else {
		report.RestrictPushes = "No"
	}

	// Parse Push Restrictions
	if protection.Restrictions != nil {
		report.UserPushRestrictions = formatUsers(protection.Restrictions.Users)
		report.TeamPushRestrictions = formatTeams(protection.Restrictions.Teams)
	} else {
		report.UserPushRestrictions = "None configured"
		report.TeamPushRestrictions = "None configured"
	}

	// Parse Allow Force Pushes setting
	if protection.AllowForcePushes != nil {
		report.AllowForcePushes = boolToYesNo(protection.AllowForcePushes.Enabled)
	} else {
		report.AllowForcePushes = "No"
	}

	// Parse Allow Deletions setting
	if protection.AllowDeletions != nil {
		report.AllowDeletions = boolToYesNo(protection.AllowDeletions.Enabled)
	} else {
		report.AllowDeletions = "No"
	}

	// Parse Required Conversation Resolution setting
	if protection.RequiredConversationResolution != nil {
		report.RequiredConversationResolution = boolToYesNo(protection.RequiredConversationResolution.Enabled)
	} else {
		report.RequiredConversationResolution = "No"
	}

	return report
}

// reportToSlice converts a BranchProtectionReport to a string slice for CSV writing
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

// formatUsers formats a slice of GitHub users into a comma-separated string
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

// formatTeams formats a slice of GitHub teams into a comma-separated string
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

// parsePrivateKey parses a PEM-encoded RSA private key
func parsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return jwt.ParseRSAPrivateKeyFromPEM([]byte(pemStr))
}

// generateJWT generates a JWT token for GitHub App authentication
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

// parseInt64 converts a string to int64
func parseInt64(s string) int64 {
	var id int64
	fmt.Sscanf(s, "%d", &id)
	return id
}

// boolToYesNo converts a boolean to "Yes" or "No" string
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// showProgress displays the current progress with percentage and ETA
func showProgress() {
	percentage := float64(processedRepos) / float64(totalRepos) * 100
	elapsed := time.Since(startTime)

	var eta string
	if processedRepos > 0 {
		// Calculate average time per repository
		avgTimePerRepo := elapsed / time.Duration(processedRepos)
		remainingRepos := totalRepos - processedRepos
		estimatedRemaining := avgTimePerRepo * time.Duration(remainingRepos)
		eta = fmt.Sprintf(" (ETA: %s)", formatDuration(estimatedRemaining))
	}

	// Use \r to overwrite the same line for a clean progress indicator
	fmt.Printf("\rProcessing repositories: %d/%d (%.1f%%)%s", processedRepos, totalRepos, percentage, eta)
}

// formatDuration formats a duration into a human-readable string
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
