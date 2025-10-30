package main

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v53/github"
	"github.com/xuri/excelize/v2"
)

type workbookContext struct {
	file             *excelize.File
	allReposSheet    string
	engineeringSheet string
	headers          []string
	engHeaders       []string
}

type engineeringSummary struct {
	total             int
	protected         int
	unprotected       int
	evaluateOnly      int
	activeProtected   int
	activeUnprotected int
}

func runAudit(ctx context.Context, client *github.Client, org string, logger *Logger, rateLimitHandler *RateLimitHandler) error {
	resetGlobalCounters()

	repos, err := fetchOrgRepositories(ctx, client, org, rateLimitHandler, logger)
	if err != nil {
		return err
	}

	totalRepos = len(repos)
	logger.Info("Repository discovery complete", map[string]interface{}{
		"total_repositories": totalRepos,
		"organization":       org,
	})

	fmt.Println("Starting GitHub Branch Protection Report Scanner...")

	wb, err := initializeWorkbook()
	if err != nil {
		return err
	}

	sort.Slice(repos, func(i, j int) bool {
		return repos[i].GetPushedAt().Time.After(repos[j].GetPushedAt().Time)
	})

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 10)

	protected, unprotected := 0, 0
	activeProtected, activeUnprotected := 0, 0

	allReposRow := 2
	for _, repo := range repos {
		wg.Add(1)
		semaphore <- struct{}{}

		go func(repo *github.Repository, row int) {
			defer wg.Done()
			defer func() { <-semaphore }()

			report := processRepository(ctx, client, org, repo, logger, rateLimitHandler, false)
			mergeRulesetsIntoReport(ctx, client, org, repo, logger, rateLimitHandler, report)

			mu.Lock()
			processedRepos++
			showProgress()

			if report != nil {
				report.LastActivity = repo.GetPushedAt().Time.Format("02 Jan 2006 15:04 MST")
				values := reportToSlice(report)
				for i, v := range values {
					cell, _ := excelize.CoordinatesToCellName(i+1, row)
					wb.file.SetCellValue(wb.allReposSheet, cell, v)
				}
			}

			isProtected, viaClassic, viaRuleset, viaBoth, isEvaluateOnly := classifyProtection(report)

			if isProtected {
				protected++
				switch {
				case viaBoth:
					protectedBoth++
				case viaClassic:
					protectedClassic++
				case viaRuleset:
					protectedRuleset++
				}
			} else {
				if isEvaluateOnly {
					evaluateOnly++
				} else {
					unprotected++
				}
			}

			pushedAt := repo.GetPushedAt().Time
			isActive := time.Since(pushedAt).Hours() <= 90*24
			if isActive {
				if isProtected {
					activeProtected++
					switch {
					case viaBoth:
						activeProtectedBoth++
					case viaClassic:
						activeProtectedClassic++
					case viaRuleset:
						activeProtectedRuleset++
					}
				} else {
					if isEvaluateOnly {
						activeEvaluateOnly++
					} else {
						activeUnprotected++
					}
				}
			}

			if report != nil {
				if report.RequirePullRequestBeforeMerging == "No" {
					noProtection++
					if isActive {
						activeNoProtection++
					}
				}
				if report.RequireApprovals == "No" {
					noPRRequired++
					if isActive {
						activeNoPRRequired++
					}
				}
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
				if report.AllowForcePushes == "Yes" {
					allowPushes++
					if isActive {
						activeAllowPushes++
					}
				}
			}
			mu.Unlock()
		}(repo, allReposRow)
		allReposRow++
	}

	wg.Wait()
	fmt.Println()

	protectedPercentage := 0.0
	if totalRepos > 0 {
		protectedPercentage = float64(protected) / float64(totalRepos) * 100
	}
	fmt.Printf("\nSummary:\n")
	fmt.Printf("- %.1f%% (%d) repositories require PRs before merge\n", protectedPercentage, protected)
	fmt.Printf("- %d repositories rely on classic branch protection\n", protectedClassic)
	fmt.Printf("- %d repositories rely on rulesets\n", protectedRuleset)
	fmt.Printf("- %d repositories rely on both classic protection and rulesets\n", protectedBoth)
	fmt.Printf("- %d repositories have rulesets in evaluate mode only\n", evaluateOnly)
	fmt.Printf("- %d repositories do not require PRs before merge\n", unprotected)

	activeTotal := activeProtected + activeUnprotected + activeEvaluateOnly
	if activeTotal > 0 {
		fmt.Printf("\nActive Repository Summary:\n")
		fmt.Printf("- %d active repositories require PRs before merge\n", activeProtected)
		fmt.Printf("- %d active repositories do not require PRs before merge\n", activeUnprotected)
		fmt.Printf("- %d active repositories have evaluate-only rulesets\n", activeEvaluateOnly)
	}

	if totalRepos > 0 {
		fmt.Printf("\nDetailed Summary (All Repos):\n")
		fmt.Printf("- %.1f%% (%d) have no branch protection\n", float64(noProtection)/float64(totalRepos)*100, noProtection)
		fmt.Printf("- %.1f%% (%d) don’t require PR reviews before merging\n", float64(noPRRequired)/float64(totalRepos)*100, noPRRequired)
		fmt.Printf("- %.1f%% (%d) require exactly 1 approval\n", float64(oneApproval)/float64(totalRepos)*100, oneApproval)
		fmt.Printf("- %.1f%% (%d) require 2–3 approvals\n", float64(twoToThreeApprovals)/float64(totalRepos)*100, twoToThreeApprovals)
		fmt.Printf("- %.1f%% (%d) allow force pushes\n", float64(allowPushes)/float64(totalRepos)*100, allowPushes)
	}

	activeTotal = activeProtected + activeUnprotected + activeEvaluateOnly
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
	fmt.Println("::endgroup::")

	fmt.Println("::group::Engineering Team Summary")
	engSummary, err := processEngineeringSummary(ctx, client, org, rateLimitHandler, logger, wb)
	if err != nil {
		return err
	}

	fmt.Printf("Engineering Team Repositories: %d\n", engSummary.total)
	fmt.Printf("Protected branches found (require PR before merge): %d\n", engSummary.protected)
	fmt.Printf("Unprotected or inaccessible branches (no PR rules or API denied): %d\n", engSummary.unprotected)
	engActiveTotal := engSummary.activeProtected + engSummary.activeUnprotected
	fmt.Printf("Active Repositories (last 90 days): %d\n", engActiveTotal)
	fmt.Printf("Active protected (require PR before merge): %d\n", engSummary.activeProtected)
	fmt.Printf("Active unprotected or inaccessible: %d\n", engSummary.activeUnprotected)
	if engSummary.total > 0 {
		fmt.Printf("\nDetailed Summary (Engineering Teams):\n")
	}
	fmt.Println("::endgroup::")

	if err := wb.file.SaveAs("branch_protection_report.xlsx"); err != nil {
		return fmt.Errorf("save Excel file: %w", err)
	}

	return nil
}

func fetchOrgRepositories(ctx context.Context, client *github.Client, org string, rateLimitHandler *RateLimitHandler, logger *Logger) ([]*github.Repository, error) {
	var repos []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		Type:        "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	for {
		batch, resp, err := client.Repositories.ListByOrg(ctx, org, opt)
		if err != nil {
			logger.Error("Failed to list repositories", map[string]interface{}{"error": err.Error()})
			return nil, fmt.Errorf("list repositories: %w", err)
		}
		rateLimitHandler.HandleRateLimit(resp, logger)
		repos = append(repos, batch...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}
	return repos, nil
}

func initializeWorkbook() (*workbookContext, error) {
	excelFile := excelize.NewFile()
	allReposSheet := "AllRepos"
	engineeringSheet := "Engineering"
	excelFile.NewSheet(allReposSheet)
	excelFile.NewSheet(engineeringSheet)
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
		"Protection Source",
		"Ruleset Enforcement",
		"Ruleset Names",
		"Effective PR Required",
		"Effective Approvals Required",
		"Effective Force Pushes Blocked",
	}

	engHeaders := append(append([]string{}, headers...), "Engineering Teams")

	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		excelFile.SetCellValue(allReposSheet, cell, h)
	}
	for i, h := range engHeaders {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		excelFile.SetCellValue(engineeringSheet, cell, h)
	}
	for i := 1; i <= len(engHeaders); i++ {
		col, _ := excelize.ColumnNumberToName(i)
		excelFile.SetColWidth(allReposSheet, col, col, 26)
		excelFile.SetColWidth(engineeringSheet, col, col, 26)
	}

	return &workbookContext{
		file:             excelFile,
		allReposSheet:    allReposSheet,
		engineeringSheet: engineeringSheet,
		headers:          headers,
		engHeaders:       engHeaders,
	}, nil
}

func processEngineeringSummary(ctx context.Context, client *github.Client, org string, rateLimitHandler *RateLimitHandler, logger *Logger, wb *workbookContext) (*engineeringSummary, error) {
	var engineeringTeams []*github.Team
	teamOpt := &github.ListOptions{PerPage: 100}
	for {
		teams, resp, err := client.Teams.ListTeams(ctx, org, teamOpt)
		if err != nil {
			logger.Error("Failed to list teams", map[string]interface{}{"error": err.Error()})
			return nil, fmt.Errorf("list teams: %w", err)
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

	engineeringReposMap := map[int64]*github.Repository{}
	engRepoTeams := make(map[int64]map[string]struct{})
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

	engRepoReports := make(map[int64]*BranchProtectionReport)
	summary := &engineeringSummary{}

	for repoID, repo := range engineeringReposMap {
		report := processRepository(ctx, client, org, repo, logger, rateLimitHandler, true)
		mergeRulesetsIntoReport(ctx, client, org, repo, logger, rateLimitHandler, report)
		engRepoReports[repoID] = report

		isProtected, _, _, _, isEvaluateOnly := classifyProtection(report)
		if isProtected {
			summary.protected++
		} else {
			if isEvaluateOnly {
				summary.evaluateOnly++
			} else {
				summary.unprotected++
			}
		}

		pushedAt := repo.GetPushedAt().Time
		isActive := time.Since(pushedAt).Hours() <= 90*24
		if isActive {
			if isProtected {
				summary.activeProtected++
			} else {
				summary.activeUnprotected++
			}
		}
	}

	summary.total = len(engineeringReposMap)

	ids := make([]int64, 0, len(engRepoReports))
	for id := range engRepoReports {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		return engineeringReposMap[ids[i]].GetName() < engineeringReposMap[ids[j]].GetName()
	})

	row := 2
	for _, repoID := range ids {
		report := engRepoReports[repoID]
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
		values = append(values, strings.Join(teamList, ", "))
		for i, v := range values {
			cell, _ := excelize.CoordinatesToCellName(i+1, row)
			wb.file.SetCellValue(wb.engineeringSheet, cell, v)
		}
		row++
	}

	return summary, nil
}
