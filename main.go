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

var (
	totalRepos      int
	processedRepos  int
	startTime       time.Time
	errorMessages   []string
	warningMessages []string
	mu              sync.Mutex
)

func main() {
	startTime = time.Now()

	appID := os.Getenv("APP_ID")
	installationID := os.Getenv("INSTALLATION_ID")
	privateKeyPEM := os.Getenv("PRIVATE_KEY")
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		org = "nanasec"
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
	jwtClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken}))
	client := github.NewClient(jwtClient)

	token, _, err := client.Apps.CreateInstallationToken(ctx, parseInt64(installationID), nil)
	if err != nil {
		log.Fatalf("Failed to create installation token: %v", err)
	}

	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.GetToken()}))
	client = github.NewClient(tc)

	repos, _, err := client.Repositories.ListByOrg(ctx, org, &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		log.Fatalf("Failed to list repositories: %v", err)
	}

	totalRepos = len(repos)

	// Start Progress Updates group
	fmt.Printf("::group::Progress Updates\n")
	fmt.Printf("Found %d repositories. Starting scan...\n", totalRepos)

	csvFile, err := os.Create("branch_protection_report.csv")
	if err != nil {
		log.Fatalf("Could not create CSV file: %v", err)
	}
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)
	defer writer.Flush()

	// CSV headers for report
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

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Concurrency limiter

	protected, unprotected := 0, 0

	// Start Debug Logs group (after Progress Updates for better separation)
	fmt.Printf("::endgroup::\n") // End Progress Updates group early so logs don't mix
	fmt.Printf("::group::Debug Logs\n")

	for _, repo := range repos {
		wg.Add(1)
		go func(repo *github.Repository) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			report := processRepository(ctx, client, org, repo)

			mu.Lock()
			defer mu.Unlock()

			processedRepos++
			// Reopen Progress Updates group temporarily to update progress bar cleanly
			fmt.Printf("::group::Progress Updates\n")
			showProgress()
			fmt.Printf("::endgroup::\n")

			if report != nil {
				if err := writer.Write(reportToSlice(report)); err != nil {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to write report for %s: %v", repo.GetName(), err))
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

	// End Debug Logs group
	fmt.Printf("::endgroup::\n") // Close Debug Logs group

	// Start Summary group
	fmt.Printf("::group::Summary\n")

	elapsed := time.Since(startTime).Seconds()
	fmt.Println("Scan complete.")
	fmt.Printf("Repositories scanned: %d\n", totalRepos)
	fmt.Printf("Protected branches found: %d\n", protected)
	fmt.Printf("Unprotected or inaccessible branches: %d\n", unprotected)
	fmt.Printf("Total time taken: %.2f seconds\n", elapsed)

	if len(errorMessages) > 0 {
		fmt.Printf("\nErrors encountered (%d):\n", len(errorMessages))
		for _, msg := range errorMessages {
			fmt.Printf("  - %s\n", msg)
		}
	}

	if len(warningMessages) > 0 {
		fmt.Printf("\nWarnings (%d):\n", len(warningMessages))
		for _, msg := range warningMessages {
			fmt.Printf("  - %s\n", msg)
		}
	}

	fmt.Println("CSV report saved as branch_protection_report.csv")
	// End Summary group
	fmt.Printf("::endgroup::\n")
}

func processRepository(ctx context.Context, client *github.Client, org string, repo *github.Repository) *BranchProtectionReport {
	repoName := repo.GetName()
	defaultBranch := repo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	// Detailed log for each repository
	fmt.Printf("Processing: %s/%s (branch: %s)\n", org, repoName, defaultBranch)

	protection, resp, err := client.Repositories.GetBranchProtection(ctx, org, repoName, defaultBranch)
	if err != nil {
		if resp != nil && resp.StatusCode == 404 {
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
		mu.Lock()
		errorMessages = append(errorMessages, fmt.Sprintf("Failed to get protection for %s/%s: %v", org, repoName, err))
		mu.Unlock()
		return nil
	}

	return parseProtectionToReport(repoName, defaultBranch, protection)
}

func parseProtectionToReport(repoName, branch string, protection *github.Protection) *BranchProtectionReport {
	report := &BranchProtectionReport{Repository: repoName, Branch: branch}

	if protection.RequiredPullRequestReviews != nil {
		pr := protection.RequiredPullRequestReviews
		report.RequirePullRequestBeforeMerging = "Yes"
		report.RequireApprovals = boolToYesNo(pr.RequiredApprovingReviewCount > 0)
		report.RequiredNumberOfApprovals = strconv.Itoa(pr.RequiredApprovingReviewCount)
		report.DismissStaleReviews = boolToYesNo(pr.DismissStaleReviews)
		report.RequireCodeOwnerReviews = boolToYesNo(pr.RequireCodeOwnerReviews)
		report.RequireApprovalOfMostRecentPush = boolToYesNo(pr.RequireLastPushApproval)
		if pr.DismissalRestrictions != nil {
			report.RestrictWhoCanDismissReviews = formatUsers(pr.DismissalRestrictions.Users)
			report.TeamsOrAppsCanDismissReviews = formatTeams(pr.DismissalRestrictions.Teams)
		} else {
			report.RestrictWhoCanDismissReviews = "None configured"
			report.TeamsOrAppsCanDismissReviews = "None configured"
		}
		if pr.BypassPullRequestAllowances != nil {
			report.BypassAllowanceUsers = formatUsers(pr.BypassPullRequestAllowances.Users)
			report.BypassAllowanceTeams = formatTeams(pr.BypassPullRequestAllowances.Teams)
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

	if protection.RequiredStatusChecks != nil {
		sc := protection.RequiredStatusChecks
		if len(sc.Contexts) > 0 {
			report.RequiredStatusChecks = strings.Join(sc.Contexts, ", ")
		} else {
			report.RequiredStatusChecks = "None configured"
		}
		report.StatusChecksStrict = boolToYesNo(sc.Strict)
	} else {
		report.RequiredStatusChecks = "None configured"
		report.StatusChecksStrict = "No"
	}

	if protection.EnforceAdmins != nil {
		report.EnforceAdmins = boolToYesNo(protection.EnforceAdmins.Enabled)
	} else {
		report.EnforceAdmins = "No"
	}

	if protection.RequiredSignatures != nil && protection.RequiredSignatures.Enabled != nil {
		report.RequireSignedCommits = boolToYesNo(*protection.RequiredSignatures.Enabled)
	} else {
		report.RequireSignedCommits = "No"
	}

	report.RequireLinearHistory = "No"

	if protection.AllowForkSyncing != nil && protection.AllowForkSyncing.Enabled != nil {
		report.AllowForkSyncing = boolToYesNo(*protection.AllowForkSyncing.Enabled)
	} else {
		report.AllowForkSyncing = "No"
	}

	if protection.LockBranch != nil && protection.LockBranch.Enabled != nil {
		report.LockBranch = boolToYesNo(*protection.LockBranch.Enabled)
	} else {
		report.LockBranch = "No"
	}

	if protection.BlockCreations != nil && protection.BlockCreations.Enabled != nil {
		report.RestrictPushes = boolToYesNo(*protection.BlockCreations.Enabled)
	} else {
		report.RestrictPushes = "No"
	}

	if protection.Restrictions != nil {
		report.UserPushRestrictions = formatUsers(protection.Restrictions.Users)
		report.TeamPushRestrictions = formatTeams(protection.Restrictions.Teams)
	} else {
		report.UserPushRestrictions = "None configured"
		report.TeamPushRestrictions = "None configured"
	}

	if protection.AllowForcePushes != nil {
		report.AllowForcePushes = boolToYesNo(protection.AllowForcePushes.Enabled)
	} else {
		report.AllowForcePushes = "No"
	}

	if protection.AllowDeletions != nil {
		report.AllowDeletions = boolToYesNo(protection.AllowDeletions.Enabled)
	} else {
		report.AllowDeletions = "No"
	}

	if protection.RequiredConversationResolution != nil {
		report.RequiredConversationResolution = boolToYesNo(protection.RequiredConversationResolution.Enabled)
	} else {
		report.RequiredConversationResolution = "No"
	}

	return report
}

func reportToSlice(r *BranchProtectionReport) []string {
	return []string{
		r.Repository, r.Branch, r.RequirePullRequestBeforeMerging, r.RequireApprovals,
		r.RequiredNumberOfApprovals, r.DismissStaleReviews, r.RequireCodeOwnerReviews,
		r.RestrictWhoCanDismissReviews, r.TeamsOrAppsCanDismissReviews, r.BypassAllowanceUsers,
		r.BypassAllowanceTeams, r.RequireApprovalOfMostRecentPush, r.RequiredStatusChecks,
		r.StatusChecksStrict, r.RequiredConversationResolution, r.RequireSignedCommits,
		r.RequireLinearHistory, r.AllowForkSyncing, r.LockBranch, r.EnforceAdmins,
		r.RestrictPushes, r.UserPushRestrictions, r.TeamPushRestrictions,
		r.AllowForcePushes, r.AllowDeletions,
	}
}

func formatUsers(users []*github.User) string {
	if len(users) == 0 {
		return "None configured"
	}
	names := make([]string, len(users))
	for i, u := range users {
		names[i] = u.GetLogin()
	}
	return strings.Join(names, ", ")
}

func formatTeams(teams []*github.Team) string {
	if len(teams) == 0 {
		return "None configured"
	}
	names := make([]string, len(teams))
	for i, t := range teams {
		names[i] = t.GetSlug()
	}
	return strings.Join(names, ", ")
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
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    appID,
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
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

func showProgress() {
	percentage := float64(processedRepos) / float64(totalRepos) * 100
	elapsed := time.Since(startTime)
	var eta string
	if processedRepos > 0 {
		avg := elapsed / time.Duration(processedRepos)
		remaining := totalRepos - processedRepos
		estimatedRemaining := avg * time.Duration(remaining)
		eta = fmt.Sprintf(" (ETA: %s)", formatDuration(estimatedRemaining))
	}
	fmt.Printf("\rProcessing repositories: %d/%d (%.1f%%)%s", processedRepos, totalRepos, percentage, eta)
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}
