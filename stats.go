package main

import (
	"fmt"
	"sync"
	"time"
)

var (
	totalRepos      int
	processedRepos  int
	startTime       time.Time
	errorMessages   []string
	warningMessages []string
	mu              sync.Mutex

	// Detailed counters (all repos)
	noProtection, noPRRequired, oneApproval, twoToThreeApprovals, allowPushes                               int
	activeNoProtection, activeNoPRRequired, activeOneApproval, activeTwoToThreeApprovals, activeAllowPushes int

	// Counters by protection source
	protectedClassic, protectedRuleset, protectedBoth, evaluateOnly                         int
	activeProtectedClassic, activeProtectedRuleset, activeProtectedBoth, activeEvaluateOnly int
)

func resetGlobalCounters() {
	processedRepos = 0
	totalRepos = 0
	errorMessages = nil
	warningMessages = nil

	noProtection = 0
	noPRRequired = 0
	oneApproval = 0
	twoToThreeApprovals = 0
	allowPushes = 0
	activeNoProtection = 0
	activeNoPRRequired = 0
	activeOneApproval = 0
	activeTwoToThreeApprovals = 0
	activeAllowPushes = 0

	protectedClassic = 0
	protectedRuleset = 0
	protectedBoth = 0
	evaluateOnly = 0
	activeProtectedClassic = 0
	activeProtectedRuleset = 0
	activeProtectedBoth = 0
	activeEvaluateOnly = 0
}

func showProgress() {
	if totalRepos == 0 {
		return
	}

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
