package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-github/v53/github"
)

// Minimal ruleset representations used for effective rules calculations.
type ruleset struct {
	Name         string             `json:"name"`
	Enforcement  string             `json:"enforcement"`
	Targets      json.RawMessage    `json:"target,omitempty"`
	BypassActors []json.RawMessage  `json:"bypass_actors,omitempty"`
	Rules        []rulesetRule      `json:"rules"`
	Conditions   *rulesetConditions `json:"conditions,omitempty"`
}

type rulesetConditions struct {
	RefName *struct {
		Include []string `json:"include"`
		Exclude []string `json:"exclude"`
	} `json:"ref_name,omitempty"`
}

type rulesetRule struct {
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
}

type effectiveRules struct {
	HasPRRequiredActive bool
	ApprovalsActive     int
	ForceBlockedActive  *bool

	HasPRRequiredEvaluate bool
	ApprovalsEvaluate     int
	ForceBlockedEvaluate  *bool

	EnforcementLabel string
	Names            []string
	Source           string
}

func fetchRepoRulesets(ctx context.Context, client *github.Client, org, repo string, rl *RateLimitHandler, logger *Logger) ([]ruleset, bool, error) {
	u := &url.URL{
		Path: path.Join("repos", org, repo, "rulesets"),
	}
	q := u.Query()
	q.Set("includes_parents", "true")
	u.RawQuery = q.Encode()

	req, err := client.NewRequest("GET", u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	var rs []ruleset
	resp, err := client.Do(ctx, req, &rs)
	rl.HandleRateLimit(resp, logger)
	if err != nil {
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			return nil, true, fmt.Errorf("rulesets API inaccessible: %w", err)
		}
		return nil, false, err
	}
	logger.Info("Fetched rulesets", map[string]interface{}{
		"repo":  repo,
		"count": len(rs),
	})
	return rs, false, nil
}

func computeEffectiveFromRulesets(rs []ruleset, defaultBranch string, logger *Logger) effectiveRules {
	var eff effectiveRules
	eff.EnforcementLabel = "None"
	activeFound := false

	for _, r := range rs {
		if !rulesetTargetsBranch(r, defaultBranch, logger) {
			logger.Info("Ruleset skipped due to branch targeting", map[string]interface{}{
				"ruleset": r.Name,
				"branch":  defaultBranch,
			})
			continue
		}
		enf := normalizeEnforcementLabel(r.Enforcement)
		switch enf {
		case "Active":
			activeFound = true
			eff.EnforcementLabel = "Active"
			eff.Names = append(eff.Names, r.Name)
			applyRuleAggregate(&eff, r, true)
		case "Evaluate":
			if !activeFound {
				eff.EnforcementLabel = "Evaluate"
			}
			eff.Names = append(eff.Names, r.Name)
			applyRuleAggregate(&eff, r, false)
		case "Disabled":
			// Ignore disabled rulesets for effective calculation.
		default:
			// Leave label unchanged for unknown values.
		}
	}

	return eff
}

func normalizeEnforcementLabel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "active":
		return "Active"
	case "evaluate":
		return "Evaluate"
	case "disabled":
		return "Disabled"
	case "none", "":
		return "None"
	default:
		return strings.Title(strings.ToLower(v))
	}
}

// --- ✅ ROBUST BRANCH TARGET MATCHING LOGIC BELOW ---

func rulesetTargetsBranch(r ruleset, branch string, logger *Logger) bool {
	if r.Conditions == nil || r.Conditions.RefName == nil {
		logger.Info("Ruleset has no ref_name conditions; assuming not targeted", map[string]interface{}{
			"ruleset": r.Name,
			"branch":  branch,
		})
		return false
	}

	includes := r.Conditions.RefName.Include
	excludes := r.Conditions.RefName.Exclude

	if len(includes) == 0 && len(excludes) == 0 {
		logger.Info("Ruleset has empty include/exclude; assuming not targeted", map[string]interface{}{
			"ruleset": r.Name,
			"branch":  branch,
		})
		return false
	}

	matched := false
	for _, inc := range includes {
		if robustGlobMatch(inc, branch) {
			matched = true
			break
		}
	}

	if !matched {
		logger.Info("Ruleset did not match include patterns", map[string]interface{}{
			"ruleset": r.Name,
			"branch":  branch,
			"include": includes,
		})
		return false
	}

	for _, exc := range excludes {
		if robustGlobMatch(exc, branch) {
			logger.Info("Ruleset excluded branch", map[string]interface{}{
				"ruleset": r.Name,
				"branch":  branch,
				"exclude": excludes,
			})
			return false
		}
	}

	logger.Info("Ruleset matched branch successfully", map[string]interface{}{
		"ruleset": r.Name,
		"branch":  branch,
		"include": includes,
		"exclude": excludes,
	})
	return true
}

// --- ✅ ROBUST GLOB MATCH FUNCTION ---

func robustGlobMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}

	// GitHub’s patterns use "**" and "*" for wildcards
	pattern = strings.ReplaceAll(pattern, "**", "*")

	// Special case: "*" means match everything
	if pattern == "*" {
		return true
	}

	// Exact match (case-insensitive)
	if strings.EqualFold(pattern, value) {
		return true
	}

	// Convert pattern to a regular expression
	rePattern := regexp.QuoteMeta(pattern)
	rePattern = strings.ReplaceAll(rePattern, "\\*", ".*")
	rePattern = "^" + rePattern + "$"

	re, err := regexp.Compile("(?i)" + rePattern) // case-insensitive
	if err != nil {
		// fallback: simple equality check
		return strings.EqualFold(pattern, value)
	}
	return re.MatchString(value)
}

// --- END OF ROBUST MATCHER ---

func applyRuleAggregate(e *effectiveRules, rs ruleset, active bool) {
	for _, rule := range rs.Rules {
		switch strings.ToLower(rule.Type) {
		case "pull_request":
			if active {
				e.HasPRRequiredActive = true
			} else {
				e.HasPRRequiredEvaluate = true
			}
		case "required_status_checks":
			// Informational, ignore for effectiveness.
		case "non_fast_forward", "block_force_pushes":
			val := true
			if active {
				e.ForceBlockedActive = &val
			} else {
				e.ForceBlockedEvaluate = &val
			}
		case "signed_commits":
			// Informational only.
		case "approvals", "required_pull_request_reviews":
			minA := extractIntParam(rule.Parameters, []string{"min_approvals", "required_approvals"})
			if active {
				if minA > e.ApprovalsActive {
					e.ApprovalsActive = minA
				}
			} else if minA > e.ApprovalsEvaluate {
				e.ApprovalsEvaluate = minA
			}
		default:
			// Unhandled rule types ignored.
		}
	}
}

func extractIntParam(params map[string]interface{}, keys []string) int {
	for _, k := range keys {
		if v, ok := params[k]; ok {
			switch t := v.(type) {
			case float64:
				return int(t)
			case int:
				return t
			case json.Number:
				i, _ := t.Int64()
				return int(i)
			case string:
				i, _ := strconv.Atoi(t)
				return i
			}
		}
	}
	return 0
}
