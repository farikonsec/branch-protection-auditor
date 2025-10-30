package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
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
	return rs, false, nil
}

func computeEffectiveFromRulesets(rs []ruleset, defaultBranch string) effectiveRules {
	var eff effectiveRules
	eff.EnforcementLabel = "None"
	activeFound := false

	for _, r := range rs {
		if !rulesetTargetsBranch(r, defaultBranch) {
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

func rulesetTargetsBranch(r ruleset, branch string) bool {
	if r.Conditions != nil && r.Conditions.RefName != nil {
		incl := r.Conditions.RefName.Include
		excl := r.Conditions.RefName.Exclude
		if len(incl) > 0 {
			match := false
			for _, patt := range incl {
				if globMatch(patt, branch) {
					match = true
					break
				}
			}
			if !match {
				return false
			}
		}
		for _, patt := range excl {
			if globMatch(patt, branch) {
				return false
			}
		}
		return true
	}
	return false
}

func globMatch(pattern, s string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false
	}
	p := strings.ReplaceAll(pattern, "**", "*")
	ok, err := path.Match(p, s)
	if err != nil {
		return strings.EqualFold(pattern, s)
	}
	return ok
}

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
