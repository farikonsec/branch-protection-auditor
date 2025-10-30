package main

// BranchProtectionReport represents the collected configuration for a repository's default branch.
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

	ProtectionSource            string
	RulesetEnforcement          string
	RulesetNames                string
	EffectivePRRequired         string
	EffectiveApprovalsRequired  string
	EffectiveForcePushesBlocked string
}
