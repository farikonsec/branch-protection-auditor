//go:build archive
// +build archive

// this is older version that only checks legacy protection. it works. just keep for archive.
package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-github/v53/github"
	"github.com/xuri/excelize/v2"
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
	LastActivity                    string
}

var (
	totalRepos      int
	processedRepos  int
	startTime       time.Time
	errorMessages   []string
	warningMessages []string
	mu              sync.Mutex

	// New counters for detailed summary
	noProtection, noPRRequired, oneApproval, twoToThreeApprovals, allowPushes                               int
	activeNoProtection, activeNoPRRequired, activeOneApproval, activeTwoToThreeApprovals, activeAllowPushes int
)

type Logger struct {
	mu sync.Mutex
}

func (l *Logger) Info(message string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	logEntry := map[string]interface{}{
		"level":   "INFO",
		"message": message,
	}
	for k, v := range fields {
		logEntry[k] = v
	}
	b, err := jsonMarshal(logEntry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}
	fmt.Println(string(b))
}

func (l *Logger) Error(message string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	logEntry := map[string]interface{}{
		"level":   "ERROR",
		"message": message,
	}
	for k, v := range fields {
		logEntry[k] = v
	}
	b, err := jsonMarshal(logEntry)
	if err != nil {
		log.Printf("Failed to marshal log entry: %v", err)
		return
	}
	fmt.Println(string(b))
}

func jsonMarshal(v interface{}) ([]byte, error) {
	// Use standard json.Marshal but import "encoding/json" here
	// to avoid import clutter at top, define inline
	// This is a helper to keep code self-contained.
	// Alternatively just import encoding/json at top.
	return json.Marshal(v)
}

type RateLimitHandler struct {
	mu sync.Mutex
}

func (r *RateLimitHandler) HandleRateLimit(resp *github.Response, logger *Logger) {
	if resp == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	remaining := resp.Rate.Remaining
	reset := resp.Rate.Reset.Time
	if remaining == 0 {
		waitDuration := time.Until(reset)
		logger.Info("Rate limit reached, sleeping until reset", map[string]interface{}{
			"reset_time": reset.Format(time.RFC3339),
			"wait_time":  waitDuration.String(),
		})
		time.Sleep(waitDuration)
	}
}

func main() {
	startTime = time.Now()

	fmt.Println("::group::Logs")

	logger := &Logger{}
	rateLimitHandler := &RateLimitHandler{}

	appID := os.Getenv("APP_ID")
	installationID := os.Getenv("INSTALLATION_ID")
	privateKeyPEM := os.Getenv("PRIVATE_KEY")
	org := os.Getenv("GITHUB_ORG")
	if org == "" {
		org = "nanasec"
	}
	if appID == "" || installationID == "" || privateKeyPEM == "" {
		logger.Error("Missing APP_ID, INSTALLATION_ID, or PRIVATE_KEY environment variables", nil)
		os.Exit(1)
	}

	key, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		logger.Error("Failed to parse private key", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	jwtToken, err := generateJWT(appID, key)
	if err != nil {
		logger.Error("Failed to generate JWT", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}

	logger.Info("Starting GitHub branch protection scanner", map[string]interface{}{
		"app_id":       appID,
		"organization": org,
	})

	ctx := context.Background()
	jwtClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: jwtToken}))
	client := github.NewClient(jwtClient)

	token, resp, err := client.Apps.CreateInstallationToken(ctx, parseInt64(installationID), nil)
	if err != nil {
		logger.Error("Failed to create installation token", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
	rateLimitHandler.HandleRateLimit(resp, logger)

	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token.GetToken()}))
	client = github.NewClient(tc)

	var repos []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		batch, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			logger.Error("Failed to list repositories", map[string]interface{}{"error": err.Error()})
			os.Exit(1)
		}
		rateLimitHandler.HandleRateLimit(resp, logger)
		repos = append(repos, batch...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	totalRepos = len(repos)

	logger.Info("Repository discovery complete", map[string]interface{}{
		"total_repositories": totalRepos,
		"organization":       org,
	})

	fmt.Println("Starting GitHub Branch Protection Report Scanner...")

	// --- Excelize initialization ---
	excelFile := excelize.NewFile()
	allReposSheet := "AllRepos"
	engSheet := "Engineering"
	excelFile.NewSheet(allReposSheet)
	excelFile.NewSheet(engSheet)
	excelFile.DeleteSheet("Sheet1")
	if idx, err := excelFile.GetSheetIndex(allReposSheet); err == nil {
		excelFile.SetActiveSheet(idx)
	}

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
		"Last Activity",
	}
	engHeaders := append(append([]string{}, headers...), "Engineering Teams")
	// Write headers to both sheets
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		excelFile.SetCellValue(allReposSheet, cell, h)
	}
	for i, h := range engHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		excelFile.SetCellValue(engSheet, cell, h)
	}
	// Set column width for readability
	for i := 1; i <= len(engHeaders); i++ {
		col, _ := excelize.ColumnNumberToName(i)
		excelFile.SetColWidth(allReposSheet, col, col, 26)
		excelFile.SetColWidth(engSheet, col, col, 26)
	}

	// Sort repos by pushedAt descending
	sort.Slice(repos, func(i, j int) bool {
		return repos[i].GetPushedAt().Time.After(repos[j].GetPushedAt().Time)
	})

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10) // Concurrency limiter

	protected, unprotected := 0, 0
	activeProtected, activeUnprotected := 0, 0

	// For engineering section: track team names per repo, and branch protection reports for each
	engRepoTeams := make(map[int64]map[string]struct{}) // repoID -> set of team names
	engRepoReports := make(map[int64]*BranchProtectionReport)

	// Write all repo reports to AllRepos sheet
	allReposRow := 2
	for _, repo := range repos {
		wg.Add(1)
		go func(repo *github.Repository, row int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			report := processRepository(ctx, client, org, repo, logger, rateLimitHandler, false)

			mu.Lock()
			defer mu.Unlock()

			processedRepos++
			showProgress()

			if report != nil {
				// Set LastActivity field
				report.LastActivity = repo.GetPushedAt().Time.Format("02 Jan 2006 15:04 MST")
				// Write to Excel
				for i, v := range reportToSlice(report) {
					cell, _ := excelize.CoordinatesToCellName(i+1, row)
					excelFile.SetCellValue(allReposSheet, cell, v)
				}
				if report.RequirePullRequestBeforeMerging != "No" {
					protected++
				} else {
					unprotected++
				}
			} else {
				unprotected++
			}

			// Active repo statistics
			pushedAt := repo.GetPushedAt().Time
			isActive := time.Since(pushedAt).Hours() <= 90*24
			if isActive {
				if report != nil && report.RequirePullRequestBeforeMerging != "No" {
					activeProtected++
				} else {
					activeUnprotected++
				}
			}

			// Detailed summary counters
			if report != nil {
				// No branch protection
				if report.RequirePullRequestBeforeMerging == "No" {
					noProtection++
					if isActive {
						activeNoProtection++
					}
				}
				// No PR required
				if report.RequireApprovals == "No" {
					noPRRequired++
					if isActive {
						activeNoPRRequired++
					}
				}
				// Number of approvals
				if n, err := strconv.Atoi(report.RequiredNumberOfApprovals); err == nil {
					if n == 1 {
						oneApproval++
						if isActive {
							activeOneApproval++
						}
					} else if n >= 2 && n <= 3 {
						twoToThreeApprovals++
						if isActive {
							activeTwoToThreeApprovals++
						}
					}
				}
				// Allow force pushes
				if report.AllowForcePushes == "Yes" {
					allowPushes++
					if isActive {
						activeAllowPushes++
					}
				}
			}
		}(repo, allReposRow)
		allReposRow++
	}

	wg.Wait()

	fmt.Println() // To ensure newline after progress bar
	elapsed := time.Since(startTime).Seconds()
	logger.Info("Scan complete", map[string]interface{}{
		"repositories_scanned":        totalRepos,
		"protected_branches_found":    protected,
		"unprotected_or_inaccessible": unprotected,
		"total_time_seconds":          elapsed,
		"errors_encountered_count":    len(errorMessages),
		"warnings_encountered_count":  len(warningMessages),
		"excel_report_file":           "branch_protection_report.xlsx",
	})
	fmt.Println("::endgroup::") // End Logs
	fmt.Println("::group::Summary")

	fmt.Printf("Repositories scanned: %d\n", totalRepos)
	fmt.Printf("Protected branches found (require PR before merge): %d\n", protected)
	fmt.Printf("Unprotected or inaccessible branches (no PR rules or API denied): %d\n", unprotected)
	fmt.Printf("Total time taken: %.2f seconds\n", elapsed)

	// Active (recent) repo summary
	activeTotal := activeProtected + activeUnprotected
	fmt.Printf("\nActive Repositories (last 90 days): %d\n", activeTotal)
	fmt.Printf("Active protected (require PR before merge): %d\n", activeProtected)
	fmt.Printf("Active unprotected or inaccessible (no PR rules or API denied): %d\n", activeUnprotected)

	// Detailed summary section
	fmt.Printf("\nDetailed Summary (All Repos):\n")
	if totalRepos > 0 {
		fmt.Printf("- %.1f%% (%d) have no branch protection\n", float64(noProtection)/float64(totalRepos)*100, noProtection)
		fmt.Printf("- %.1f%% (%d) don’t require PR reviews before merging\n", float64(noPRRequired)/float64(totalRepos)*100, noPRRequired)
		fmt.Printf("- %.1f%% (%d) require exactly 1 approval\n", float64(oneApproval)/float64(totalRepos)*100, oneApproval)
		fmt.Printf("- %.1f%% (%d) require 2–3 approvals\n", float64(twoToThreeApprovals)/float64(totalRepos)*100, twoToThreeApprovals)
		fmt.Printf("- %.1f%% (%d) allow force pushes\n", float64(allowPushes)/float64(totalRepos)*100, allowPushes)
	}

	activeTotal = activeProtected + activeUnprotected
	if activeTotal > 0 {
		fmt.Printf("\nDetailed Summary (Active Repos Only):\n")
		fmt.Printf("- %.1f%% (%d) have no branch protection\n", float64(activeNoProtection)/float64(activeTotal)*100, activeNoProtection)
		fmt.Printf("- %.1f%% (%d) don’t require PR reviews before merging\n", float64(activeNoPRRequired)/float64(activeTotal)*100, activeNoPRRequired)
		fmt.Printf("- %.1f%% (%d) require exactly 1 approval\n", float64(activeOneApproval)/float64(activeTotal)*100, activeOneApproval)
		fmt.Printf("- %.1f%% (%d) require 2–3 approvals\n", float64(activeTwoToThreeApprovals)/float64(activeTotal)*100, activeTwoToThreeApprovals)
		fmt.Printf("- %.1f%% (%d) allow force pushes\n", float64(activeAllowPushes)/float64(activeTotal)*100, activeAllowPushes)
	}

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

	fmt.Println("Excel report saved as branch_protection_report.xlsx")
	fmt.Println("::endgroup::") // End Summary

	// --- Engineering Teams Section ---
	// Step 1: Fetch all teams in the org
	var engineeringTeams []*github.Team
	teamOpt := &github.ListOptions{PerPage: 100}
	for {
		teams, resp, err := client.Teams.ListTeams(ctx, org, teamOpt)
		if err != nil {
			logger.Error("Failed to list teams", map[string]interface{}{"error": err.Error()})
			os.Exit(1)
		}
		rateLimitHandler.HandleRateLimit(resp, logger)
		for _, team := range teams {
			name := strings.ToLower(team.GetName())
			if strings.Contains(name, "engineering") {
				engineeringTeams = append(engineeringTeams, team)
			}
		}
		if resp.NextPage == 0 {
			break
		}
		teamOpt.Page = resp.NextPage
	}
	// Step 2: For each engineering team, fetch repos and deduplicate, and track team names per repo
	engineeringReposMap := map[int64]*github.Repository{}
	for _, team := range engineeringTeams {
		repoOpt := &github.ListOptions{PerPage: 100}
		for {
			repoBatch, resp, err := client.Teams.ListTeamReposBySlug(ctx, org, team.GetSlug(), repoOpt)
			if err != nil {
				logger.Error("Failed to list repos for team", map[string]interface{}{
					"team":  team.GetSlug(),
					"error": err.Error(),
				})
				break
			}
			rateLimitHandler.HandleRateLimit(resp, logger)
			for _, r := range repoBatch {
				engineeringReposMap[r.GetID()] = r
				if engRepoTeams[r.GetID()] == nil {
					engRepoTeams[r.GetID()] = make(map[string]struct{})
				}
				engRepoTeams[r.GetID()][team.GetName()] = struct{}{}
			}
			if resp.NextPage == 0 {
				break
			}
			repoOpt.Page = resp.NextPage
		}
	}
	// Step 3: Process engineering repos, suppress logs, store report and teams per repo
	fmt.Println("::group::Engineering Team Summary")
	engTotal := len(engineeringReposMap)
	engProtected, engUnprotected := 0, 0
	engActiveProtected, engActiveUnprotected := 0, 0
	engNoProtection, engNoPRRequired, engOneApproval, engTwoToThreeApprovals, engAllowPushes := 0, 0, 0, 0, 0
	engRow := 2
	for repoID, repo := range engineeringReposMap {
		report := processRepository(ctx, client, org, repo, logger, rateLimitHandler, true)
		engRepoReports[repoID] = report
		// No logs for suppressed run
		if report != nil {
			if report.RequirePullRequestBeforeMerging != "No" {
				engProtected++
			} else {
				engUnprotected++
			}
		} else {
			engUnprotected++
		}
		pushedAt := repo.GetPushedAt().Time
		isActive := time.Since(pushedAt).Hours() <= 90*24
		if isActive {
			if report != nil && report.RequirePullRequestBeforeMerging != "No" {
				engActiveProtected++
			} else {
				engActiveUnprotected++
			}
		}
		if report != nil {
			if report.RequirePullRequestBeforeMerging == "No" {
				engNoProtection++
			}
			if report.RequireApprovals == "No" {
				engNoPRRequired++
			}
			if n, err := strconv.Atoi(report.RequiredNumberOfApprovals); err == nil {
				if n == 1 {
					engOneApproval++
				} else if n >= 2 && n <= 3 {
					engTwoToThreeApprovals++
				}
			}
			if report.AllowForcePushes == "Yes" {
				engAllowPushes++
			}
		}
	}
	// Write engineering repos to Excel
	for repoID, report := range engRepoReports {
		if report == nil {
			continue
		}
		values := reportToSlice(report)
		teamSet := engRepoTeams[repoID]
		teamList := make([]string, 0, len(teamSet))
		for t := range teamSet {
			teamList = append(teamList, t)
		}
		sort.Strings(teamList)
		engTeamsCol := strings.Join(teamList, ", ")
		values = append(values, engTeamsCol)
		for i, v := range values {
			cell, _ := excelize.CoordinatesToCellName(i+1, engRow)
			excelFile.SetCellValue(engSheet, cell, v)
		}
		engRow++
	}
	fmt.Printf("Engineering Team Repositories: %d\n", engTotal)
	fmt.Printf("Protected branches found (require PR before merge): %d\n", engProtected)
	fmt.Printf("Unprotected or inaccessible branches (no PR rules or API denied): %d\n", engUnprotected)
	engActiveTotal := engActiveProtected + engActiveUnprotected
	fmt.Printf("Active Repositories (last 90 days): %d\n", engActiveTotal)
	fmt.Printf("Active protected (require PR before merge): %d\n", engActiveProtected)
	fmt.Printf("Active unprotected or inaccessible: %d\n", engActiveUnprotected)
	if engTotal > 0 {
		fmt.Printf("\nDetailed Summary (Engineering Teams):\n")
		fmt.Printf("- %.1f%% (%d) have no branch protection\n", float64(engNoProtection)/float64(engTotal)*100, engNoProtection)
		fmt.Printf("- %.1f%% (%d) don’t require PR reviews before merging\n", float64(engNoPRRequired)/float64(engTotal)*100, engNoPRRequired)
		fmt.Printf("- %.1f%% (%d) require exactly 1 approval\n", float64(engOneApproval)/float64(engTotal)*100, engOneApproval)
		fmt.Printf("- %.1f%% (%d) require 2–3 approvals\n", float64(engTwoToThreeApprovals)/float64(engTotal)*100, engTwoToThreeApprovals)
		fmt.Printf("- %.1f%% (%d) allow force pushes\n", float64(engAllowPushes)/float64(engTotal)*100, engAllowPushes)
	}
	fmt.Println("::endgroup::")
	// Save Excel file
	if err := excelFile.SaveAs("branch_protection_report.xlsx"); err != nil {
		logger.Error("Failed to save Excel file", map[string]interface{}{"error": err.Error()})
		os.Exit(1)
	}
}

func processRepository(ctx context.Context, client *github.Client, org string, repo *github.Repository, logger *Logger, rateLimitHandler *RateLimitHandler, suppressLogs bool) *BranchProtectionReport {
	repoName := repo.GetName()
	defaultBranch := repo.GetDefaultBranch()
	if defaultBranch == "" {
		defaultBranch = "main"
	}

	if !suppressLogs {
		logger.Info("Processing repository branch", map[string]interface{}{
			"repository": repoName,
			"branch":     defaultBranch,
		})
	}

	protection, resp, err := client.Repositories.GetBranchProtection(ctx, org, repoName, defaultBranch)
	rateLimitHandler.HandleRateLimit(resp, logger)
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
				LastActivity:                    repo.GetPushedAt().Time.Format("02 Jan 2006 15:04 MST"),
			}
		}
		mu.Lock()
		errorMessages = append(errorMessages, fmt.Sprintf("Failed to get protection for %s/%s: %v", org, repoName, err))
		mu.Unlock()
		logger.Error("Failed to get branch protection", map[string]interface{}{
			"repository": repoName,
			"branch":     defaultBranch,
			"error":      err.Error(),
		})
		return nil
	}

	report := parseProtectionToReport(repoName, defaultBranch, protection)
	report.LastActivity = repo.GetPushedAt().Time.Format("02 Jan 2006 15:04 MST")
	return report
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
		r.LastActivity,
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
