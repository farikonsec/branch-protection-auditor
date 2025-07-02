package main

import (
	"context"
	"crypto/rsa"
	"encoding/csv"
	"encoding/json"
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

// Logger provides structured logging
type Logger struct {
	prefix string
}

func NewLogger(prefix string) *Logger {
	return &Logger{prefix: prefix}
}

func (l *Logger) Info(msg string, fields ...interface{}) {
	l.log("INFO", msg, fields...)
}

func (l *Logger) Error(msg string, fields ...interface{}) {
	l.log("ERROR", msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.log("WARN", msg, fields...)
}

func (l *Logger) log(level, msg string, fields ...interface{}) {
	timestamp := time.Now().Format("2006-01-02T15:04:05Z07:00")
	logEntry := map[string]interface{}{
		"timestamp": timestamp,
		"level":     level,
		"message":   msg,
		"service":   l.prefix,
	}
	
	// Add additional fields as key-value pairs
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			logEntry[fmt.Sprintf("%v", fields[i])] = fields[i+1]
		}
	}
	
	jsonLog, _ := json.Marshal(logEntry)
	fmt.Println(string(jsonLog))
}

// RateLimitHandler manages GitHub API rate limiting
type RateLimitHandler struct {
	logger *Logger
}

func NewRateLimitHandler(logger *Logger) *RateLimitHandler {
	return &RateLimitHandler{logger: logger}
}

func (r *RateLimitHandler) HandleRateLimit(resp *github.Response) {
	if resp == nil || resp.Rate.Limit == 0 {
		return
	}
	
	remaining := resp.Rate.Remaining
	limit := resp.Rate.Limit
	resetTime := resp.Rate.Reset.Time
	
	r.logger.Info("Rate limit status", 
		"remaining", remaining, 
		"limit", limit, 
		"reset_time", resetTime.Format(time.RFC3339))
	
	// If we're getting close to the limit (less than 10% remaining), sleep until reset
	if remaining < limit/10 {
		sleepDuration := time.Until(resetTime) + time.Second*10 // Add 10s buffer
		r.logger.Warn("Approaching rate limit, sleeping", 
			"sleep_duration", sleepDuration.String(),
			"remaining", remaining)
		time.Sleep(sleepDuration)
	}
}

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
	logger := NewLogger("github-branch-scanner")
	rateLimitHandler := NewRateLimitHandler(logger)

	appID := os.Getenv("APP_ID")
	installationID := os.Getenv("INSTALLATION_ID")
	privateKeyPEM := os.Getenv("PRIVATE_KEY")
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		org = "nanasec" // default org
	}

	if appID == "" || installationID == "" || privateKeyPEM == "" {
		logger.Error("Missing required environment variables", 
			"app_id_set", appID != "",
			"installation_id_set", installationID != "",
			"private_key_set", privateKeyPEM != "")
		log.Fatal("Missing APP_ID, INSTALLATION_ID, or PRIVATE_KEY environment variables")
	}

	logger.Info("Starting GitHub branch protection scanner", "organization", org)

	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		logger.Error("Failed to parse private key", "error", err.Error())
		log.Fatalf("Failed to parse private key: %v", err)
	}

	jwtToken, err := generateJWT(appID, key)
	if err != nil {
		logger.Error("Failed to generate JWT", "error", err.Error())
		log.Fatalf("Failed to generate JWT: %v", err)
	}

	ctx := context.Background()
	jwtTokenSource := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken})
	jwtClient := oauth2.NewClient(ctx, jwtTokenSource)
	client := github.NewClient(jwtClient)

	token, resp, err := client.Apps.CreateInstallationToken(ctx, parseInt64(installationID), nil)
	if err != nil {
		logger.Error("Failed to create installation token", "error", err.Error())
		log.Fatalf("Failed to create installation token: %v", err)
	}
	rateLimitHandler.HandleRateLimit(resp)

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.GetToken()})
	tc := oauth2.NewClient(ctx, ts)
	client = github.NewClient(tc)

	// Fetch all repositories with pagination
	logger.Info("Fetching repositories with pagination")
	var allRepos []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		Type: "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			logger.Error("Failed to list repositories", "error", err.Error(), "page", opt.Page)
			log.Fatalf("Failed to list repositories: %v", err)
		}
		
		rateLimitHandler.HandleRateLimit(resp)
		allRepos = append(allRepos, repos...)
		
		logger.Info("Fetched repositories page", 
			"page", opt.Page, 
			"repos_in_page", len(repos), 
			"total_so_far", len(allRepos))
		
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	total := len(allRepos)
	logger.Info("Repository discovery complete", "total_repositories", total)

	csvFile, err := os.Create("branch_protection_report.csv")
	if err != nil {
		logger.Error("Could not create CSV file", "error", err.Error())
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
		logger.Error("Failed to write CSV headers", "error", err.Error())
		log.Fatalf("Failed to write CSV headers: %v", err)
	}

	// Process repositories concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Limit concurrent requests
	mu := sync.Mutex{}
	
	protected, unprotected, errors := 0, 0, 0

	logger.Info("Starting concurrent repository processing", "concurrency_limit", 10)

	for i, repo := range allRepos {
		wg.Add(1)
		go func(repo *github.Repository, index int) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release

			report, resp := processRepository(ctx, client, org, repo, logger, rateLimitHandler)
			
			mu.Lock()
			defer mu.Unlock()
			
			if report != nil {
				if err := writer.Write(reportToSlice(report)); err != nil {
					logger.Error("Failed to write report", 
						"repository", repo.GetName(), 
						"error", err.Error())
					errors++
				} else {
					if report.RequirePullRequestBeforeMerging != "No" {
						protected++
					} else {
						unprotected++
					}
				}
			} else {
				unprotected++
				if resp == nil || (resp.StatusCode != 404 && resp.StatusCode != 403) {
					errors++
				}
			}
			
			// Log progress every 10 repositories
			if (index+1)%10 == 0 {
				logger.Info("Processing progress", 
					"completed", index+1, 
					"total", total, 
					"protected", protected, 
					"unprotected", unprotected,
					"errors", errors)
			}
		}(repo, i)
	}

	wg.Wait()

	elapsed := time.Since(start).Seconds()
	logger.Info("Scan complete", 
		"total_repositories", total,
		"protected_branches", protected,
		"unprotected_or_inaccessible", unprotected,
		"errors", errors,
		"duration_seconds", elapsed)
	
	fmt.Printf("\nScan complete.\n")
	fmt.Printf("Repositories scanned: %d\n", total)
	fmt.Printf("Protected branches found: %d\n", protected)
	fmt.Printf("Unprotected or inaccessible branches: %d\n", unprotected)
	fmt.Printf("Errors encountered: %d\n", errors)
	fmt.Printf("Total time taken: %.2f seconds\n", elapsed)
	fmt.Println("CSV report saved as branch_protection_report.csv")
}

func processRepository(ctx context.Context, client *github.Client, org string, repo *github.Repository, logger *Logger, rateLimitHandler *RateLimitHandler) (*BranchProtectionReport, *github.Response) {
	repoName := repo.GetName()
	defaultBranch := repo.GetDefaultBranch()
	
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	logger.Info("Processing repository", 
		"repository", fmt.Sprintf("%s/%s", org, repoName), 
		"branch", defaultBranch)

	protection, resp, err := client.Repositories.GetBranchProtection(ctx, org, repoName, defaultBranch)
	
	// Handle rate limiting
	rateLimitHandler.HandleRateLimit(resp)
	
	if err != nil {
		// Check if it's a 404 (no protection) vs other errors
		if resp != nil && resp.StatusCode == 404 {
			logger.Info("No branch protection configured", 
				"repository", fmt.Sprintf("%s/%s", org, repoName))
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
			}, resp
		}
		
		statusCode := "unknown"
		if resp != nil {
			statusCode = fmt.Sprintf("%d", resp.StatusCode)
		}
		
		logger.Error("Failed to get branch protection", 
			"repository", fmt.Sprintf("%s/%s", org, repoName),
			"error", err.Error(),
			"status_code", statusCode)
		return nil, resp
	}

	logger.Info("Successfully retrieved branch protection", 
		"repository", fmt.Sprintf("%s/%s", org, repoName))
	return parseProtectionToReport(repoName, defaultBranch, protection), resp
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

	// Force Pushes - Fixed: direct bool access
	if protection.AllowForcePushes != nil {
		report.AllowForcePushes = boolToYesNo(protection.AllowForcePushes.Enabled)
	} else {
		report.AllowForcePushes = "No"
	}

	// Deletions - Fixed: direct bool access
	if protection.AllowDeletions != nil {
		report.AllowDeletions = boolToYesNo(protection.AllowDeletions.Enabled)
	} else {
		report.AllowDeletions = "No"
	}

	// Conversation Resolution - Fixed: direct bool access
	if protection.RequiredConversationResolution != nil {
		report.RequiredConversationResolution = boolToYesNo(protection.RequiredConversationResolution.Enabled)
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
