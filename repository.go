package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-github/v53/github"
)

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
				ProtectionSource:                "None",
				RulesetEnforcement:              "None",
				RulesetNames:                    "",
				EffectivePRRequired:             "No",
				EffectiveApprovalsRequired:      "0",
				EffectiveForcePushesBlocked:     "No",
			}
		}
		mu.Lock()
		errorMessages = append(errorMessages, fmt.Sprintf("Failed to get protection for %s/%s: %v", org, repoName, err))
		mu.Unlock()
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
			ProtectionSource:                "None",
			RulesetEnforcement:              "Inaccessible",
			RulesetNames:                    "",
			EffectivePRRequired:             "No",
			EffectiveApprovalsRequired:      "0",
			EffectiveForcePushesBlocked:     "No",
		}
	}

	report := parseProtectionToReport(repoName, defaultBranch, protection)
	report.LastActivity = repo.GetPushedAt().Time.Format("02 Jan 2006 15:04 MST")
	report.ProtectionSource = "Classic Branch Protection"
	report.RulesetEnforcement = "None"
	report.RulesetNames = ""
	report.EffectivePRRequired = report.RequirePullRequestBeforeMerging
	report.EffectiveApprovalsRequired = report.RequiredNumberOfApprovals
	if report.AllowForcePushes == "Yes" {
		report.EffectiveForcePushesBlocked = "No"
	} else {
		report.EffectiveForcePushesBlocked = "Yes"
	}
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

func mergeRulesetsIntoReport(ctx context.Context, client *github.Client, org string, repo *github.Repository, logger *Logger, rl *RateLimitHandler, report *BranchProtectionReport) {
	if report == nil {
		return
	}
	repoName := repo.GetName()
	defaultBranch := report.Branch

	rs, inaccessible, err := fetchRepoRulesets(ctx, client, org, repoName, rl, logger)
	if err != nil {
		mu.Lock()
		errorMessages = append(errorMessages, fmt.Sprintf("Failed to get rulesets for %s/%s: %v", org, repoName, err))
		mu.Unlock()
		if inaccessible {
			if report.RulesetEnforcement == "" || report.RulesetEnforcement == "None" {
				report.RulesetEnforcement = "Inaccessible"
			}
		}
	}

	eff := computeEffectiveFromRulesets(rs, defaultBranch)
	report.RulesetNames = strings.Join(eff.Names, ", ")

	if eff.EnforcementLabel != "" {
		report.RulesetEnforcement = normalizeEnforcementLabel(eff.EnforcementLabel)
	} else if report.RulesetEnforcement == "" {
		report.RulesetEnforcement = "None"
	}

	classicPR := report.RequirePullRequestBeforeMerging == "Yes"
	rulesetPRActive := eff.HasPRRequiredActive
	switch {
	case classicPR && rulesetPRActive:
		report.ProtectionSource = "Both"
	case rulesetPRActive:
		report.ProtectionSource = "Ruleset"
	case classicPR:
		if report.ProtectionSource == "" {
			report.ProtectionSource = "Classic Branch Protection"
		}
	default:
		if report.ProtectionSource == "" {
			report.ProtectionSource = "None"
		}
	}

	if eff.HasPRRequiredActive {
		report.EffectivePRRequired = "Yes"
	} else if classicPR {
		report.EffectivePRRequired = "Yes"
	} else if eff.HasPRRequiredEvaluate {
		report.EffectivePRRequired = "Evaluate"
	} else {
		report.EffectivePRRequired = "No"
	}

	activeMax := eff.ApprovalsActive
	classicNum, _ := strconv.Atoi(report.RequiredNumberOfApprovals)
	if classicPR && classicNum > activeMax {
		activeMax = classicNum
	}
	if report.EffectivePRRequired == "Yes" {
		report.EffectiveApprovalsRequired = strconv.Itoa(activeMax)
	} else if report.EffectivePRRequired == "Evaluate" {
		if eff.ApprovalsEvaluate > 0 {
			report.EffectiveApprovalsRequired = fmt.Sprintf("Evaluate %d", eff.ApprovalsEvaluate)
		} else {
			report.EffectiveApprovalsRequired = "Evaluate 0"
		}
	} else {
		report.EffectiveApprovalsRequired = "0"
	}

	effBlockedActive := eff.ForceBlockedActive
	effBlockedEval := eff.ForceBlockedEvaluate
	classicBlocked := !(report.AllowForcePushes == "Yes")

	switch {
	case effBlockedActive != nil:
		report.EffectiveForcePushesBlocked = boolToYesNo(*effBlockedActive)
	case classicPR:
		report.EffectiveForcePushesBlocked = boolToYesNo(classicBlocked)
	case effBlockedEval != nil:
		report.EffectiveForcePushesBlocked = "Evaluate"
	default:
		report.EffectiveForcePushesBlocked = "No"
	}
}

func classifyProtection(report *BranchProtectionReport) (isProtected, viaClassic, viaRuleset, viaBoth, isEvaluateOnly bool) {
	if report == nil {
		return false, false, false, false, false
	}
	if strings.EqualFold(report.EffectivePRRequired, "Yes") {
		isProtected = true
	}
	switch report.ProtectionSource {
	case "Both":
		viaBoth = isProtected
	case "Classic Branch Protection":
		viaClassic = isProtected
	case "Ruleset":
		viaRuleset = isProtected
	}
	if !isProtected && strings.EqualFold(report.EffectivePRRequired, "Evaluate") {
		isEvaluateOnly = true
	}
	return
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
		r.ProtectionSource,
		r.RulesetEnforcement,
		r.RulesetNames,
		r.EffectivePRRequired,
		r.EffectiveApprovalsRequired,
		r.EffectiveForcePushesBlocked,
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

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
