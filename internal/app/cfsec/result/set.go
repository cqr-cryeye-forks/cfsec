package result

import (
	"github.com/aquasecurity/cfsec/internal/app/cfsec/resource"
)

type Set interface {
	AddResult() *Result
	WithRuleID(id string) Set
	WithLegacyRuleID(id string) Set
	WithRuleSummary(description string) Set
	WithImpact(impact string) Set
	WithResolution(resolution string) Set
	WithLinks(links []string) Set
	WithLocation(location string) Set
	All() []*Result
}

func NewSet(resourceBlock resource.Resource) *resultSet {
	return &resultSet{
		resourceBlock: resourceBlock,
	}
}

type resultSet struct {
	resourceBlock resource.Resource
	results       []*Result
	ruleID        string
	legacyID      string
	ruleSummary   string
	impact        string
	resolution    string
	location      string
	links         []string
}

func (s *resultSet) AddResult() *Result {
	result := New(s.resourceBlock).
		WithRuleID(s.ruleID).
		WithLegacyRuleID(s.legacyID).
		WithRuleSummary(s.ruleSummary).
		WithImpact(s.impact).
		WithResolution(s.resolution).
		WithLinks(s.links).
		WithLocation(s.location)
	s.results = append(s.results, result)
	return result
}

func (s *resultSet) All() []*Result {
	return s.results
}

func (r *resultSet) WithRuleID(id string) Set {
	r.ruleID = id
	return r
}

func (r *resultSet) WithLegacyRuleID(id string) Set {
	r.legacyID = id
	return r
}

func (r *resultSet) WithRuleSummary(description string) Set {
	r.ruleSummary = description
	return r
}

func (r *resultSet) WithImpact(impact string) Set {
	r.impact = impact
	return r
}

func (r *resultSet) WithResolution(resolution string) Set {
	r.resolution = resolution
	return r
}

func (r *resultSet) WithLinks(links []string) Set {
	r.links = links
	return r
}

func (r *resultSet) WithLocation(location string) Set {
	r.location = location
	return r
}