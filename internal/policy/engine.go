// SPDX-License-Identifier: Apache-2.0

// Package policy implements the AgentKnox Policy Engine. It loads
// the dual-layer policy DSL (pkg/policyspec), precompiles system predicates,
// evaluates syscall/semantic/correlated-action inputs into types.Decision
// verdicts, and derives the subset of purely system-level rules that the
// Enforcer can install pre-operation in the kernel (BPF-LSM).
//
// Evaluation model (documented, deterministic):
//   - Rules are flattened across all loaded policies in load order, then rule
//     order within each policy. Evaluation iterates top-to-bottom and the FIRST
//     rule whose selector + all present predicates match wins.
//   - A rule matches a target when: the selector matches the session's agent,
//     AND every present predicate layer (semantic/system/condition) matches. A
//     nil predicate layer imposes no constraint (matches).
//   - When no rule matches, the strongest DefaultEffect declared by any loaded
//     policy is returned (Allow if none declare one).
//   - Mode is EnforcePre when the matched rule is purely system-level
//     (When.Semantic == nil) and its effect is Block; otherwise EnforcePost.
package policy

import (
	"fmt"
	"net"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/pkg/policyspec"
	"github.com/boanlab/agentknox/pkg/types"

	"go.uber.org/zap"
)

// compiledRule is a precompiled view of one policyspec.Rule together with the
// policy-level selector and any parsed/normalized system predicate artifacts.
type compiledRule struct {
	policyName string
	selector   []string
	ruleName   string
	rule       policyspec.Rule
	effect     types.PolicyEffect

	// Precompiled system-predicate artifacts (nil/"" when absent).
	normDir string     // When.System.Dir normalized with a trailing slash
	cidr    *net.IPNet // parsed When.System.CIDR
}

// Engine is the Policy Engine. It is safe for concurrent use.
type Engine struct {
	log *zap.Logger

	mu            sync.RWMutex
	rules         []*compiledRule
	kernelRules   []pipeline.KernelRule
	defaultEffect types.PolicyEffect

	// timeline records, per session, the last time each marker (an intent class
	// or a syscall op) was observed — the substrate for After/Within predicates.
	// hasTemporal short-circuits marker recording (a per-event mutex) when no
	// loaded rule uses After/Within, the common case.
	hasTemporal atomic.Bool
	tlMu        sync.Mutex
	timeline    map[string]map[string]time.Time
}

// maxTimelineSessions bounds the temporal-timeline map (dropped on session end;
// this is the backstop if a ForgetSession is missed).
const maxTimelineSessions = 2048

// New constructs an Engine. A nil logger is tolerated (no-op logger).
func New(log *zap.Logger) *Engine {
	if log == nil {
		log = zap.NewNop()
	}
	return &Engine{
		log:           log,
		defaultEffect: types.EffectAllow,
		timeline:      make(map[string]map[string]time.Time),
	}
}

// recordMarker stamps a session marker (intent class or op) at time t, for
// After/Within predicate evaluation of later events.
func (e *Engine) recordMarker(sessID, marker string, t time.Time) {
	if !e.hasTemporal.Load() || sessID == "" || marker == "" {
		return
	}
	e.tlMu.Lock()
	defer e.tlMu.Unlock()
	m := e.timeline[sessID]
	if m == nil {
		if len(e.timeline) >= maxTimelineSessions {
			for k := range e.timeline { // evict one arbitrary stale session
				delete(e.timeline, k)
				break
			}
		}
		m = make(map[string]time.Time)
		e.timeline[sessID] = m
	}
	m[marker] = t
}

// markerSeen returns the last time a marker was recorded for a session.
func (e *Engine) markerSeen(sessID, marker string) (time.Time, bool) {
	e.tlMu.Lock()
	defer e.tlMu.Unlock()
	if m := e.timeline[sessID]; m != nil {
		t, ok := m[marker]
		return t, ok
	}
	return time.Time{}, false
}

// ForgetSession drops a session's temporal timeline (called on session end).
func (e *Engine) ForgetSession(sessID string) {
	e.tlMu.Lock()
	delete(e.timeline, sessID)
	e.tlMu.Unlock()
}

// RuleSummary is a JSON-friendly view of a loaded rule for `akctl policy`.
type RuleSummary struct {
	Name      string   `json:"name"`
	Selector  []string `json:"selector"`
	Effect    string   `json:"effect"`
	Semantic  bool     `json:"semantic"`
	System    bool     `json:"system"`
	Condition bool     `json:"condition"`
}

// Summaries returns a lightweight view of the currently loaded rules.
func (e *Engine) Summaries() []RuleSummary {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]RuleSummary, 0, len(e.rules))
	for _, cr := range e.rules {
		out = append(out, RuleSummary{
			Name:      cr.ruleName,
			Selector:  cr.selector,
			Effect:    string(cr.effect),
			Semantic:  cr.rule.When.Semantic != nil,
			System:    cr.rule.When.System != nil,
			Condition: cr.rule.When.Condition != nil,
		})
	}
	return out
}

// Load validates, precompiles, and installs the given policies, replacing any
// previously loaded set. It also derives the pre-enforceable kernel rules.
func (e *Engine) Load(policies []*policyspec.Policy) error {
	var (
		rules     []*compiledRule
		defEffect = types.EffectAllow
	)

	for _, p := range policies {
		if p == nil {
			continue
		}
		if err := p.Validate(); err != nil {
			return fmt.Errorf("policy %q: %w", p.Metadata.Name, err)
		}
		if p.Spec.DefaultEffect != "" {
			de := types.PolicyEffect(p.Spec.DefaultEffect)
			if effectRank(de) > effectRank(defEffect) {
				defEffect = de
			}
		}
		for i := range p.Spec.Rules {
			r := p.Spec.Rules[i]
			cr := &compiledRule{
				policyName: p.Metadata.Name,
				selector:   p.Spec.Selector,
				ruleName:   r.Name,
				rule:       r,
				effect:     types.PolicyEffect(r.Effect),
			}
			if sp := r.When.System; sp != nil {
				if sp.Dir != "" {
					cr.normDir = normalizeDir(sp.Dir)
				}
				if sp.CIDR != "" {
					_, ipnet, err := net.ParseCIDR(sp.CIDR)
					if err != nil {
						return fmt.Errorf("policy %q rule %q: invalid cidr %q: %w",
							p.Metadata.Name, r.Name, sp.CIDR, err)
					}
					cr.cidr = ipnet
				}
			}
			rules = append(rules, cr)
		}
	}

	kernel := deriveKernelRules(rules)

	temporal := false
	for _, cr := range rules {
		if c := cr.rule.When.Condition; c != nil && (c.After != "" || c.Within != "") {
			temporal = true
			break
		}
	}

	e.mu.Lock()
	e.rules = rules
	e.kernelRules = kernel
	e.defaultEffect = defEffect
	e.mu.Unlock()
	e.hasTemporal.Store(temporal)

	e.log.Info("policies loaded",
		zap.Int("policies", len(policies)),
		zap.Int("rules", len(rules)),
		zap.Int("kernel_rules", len(kernel)),
		zap.String("default_effect", string(defEffect)),
	)
	return nil
}

// KernelRules returns a copy of the compiled pre-enforceable rules.
func (e *Engine) KernelRules() []pipeline.KernelRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]pipeline.KernelRule, len(e.kernelRules))
	copy(out, e.kernelRules)
	return out
}

// WantsTaintedCodeBlock reports whether any Block/Kill rule matching `agent`
// forbids executing agent-written code, i.e. a rule with a semantic.provenance
// predicate and system.op == "exec". The daemon uses this to enable the
// deny-tainted-code posture for the session. The predicate is enforced in the
// kernel (bprm_check_security, and file_open for an interpreter's read), so this
// asks only whether the operator declared it, not whether an effect matched.
func (e *Engine) WantsTaintedCodeBlock(agent types.AgentKind) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, cr := range e.rules {
		if cr.effect != types.EffectBlock && cr.effect != types.EffectKill {
			continue
		}
		if !selectorMatches(cr.selector, agent) {
			continue
		}
		s, sys := cr.rule.When.Semantic, cr.rule.When.System
		if s == nil || sys == nil {
			continue
		}
		if sys.Op != "exec" {
			continue
		}
		if s.Provenance != "" {
			return true
		}
	}
	return false
}

// WantsTaintedEgressBlock reports whether any Block/Kill rule matching `agent`
// forbids an outbound connection from a taint-carrying session — i.e. a rule with
// a semantic.taint predicate and system.op == "connect". The daemon uses this to
// PRE-ARM the deny-egress posture the instant a session becomes exfil-tainted by a
// sensitive read, so the follow-on connect is refused pre-operation in the kernel
// rather than post-hoc after the first connect has already left the host.
func (e *Engine) WantsTaintedEgressBlock(agent types.AgentKind) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, cr := range e.rules {
		if cr.effect != types.EffectBlock && cr.effect != types.EffectKill {
			continue
		}
		if !selectorMatches(cr.selector, agent) {
			continue
		}
		s, sys := cr.rule.When.Semantic, cr.rule.When.System
		if s == nil || sys == nil {
			continue
		}
		if sys.Op != "connect" {
			continue
		}
		if s.Taint != "" {
			return true
		}
	}
	return false
}

// MatchFQDNBlock reports whether a purely system-level Block rule forbids
// connecting to fqdn (system.op == "connect", system.fqdn a suffix of fqdn, no
// semantic predicate). The daemon calls this on each observed DNS answer to
// decide whether to install the resolved IPs as kernel egress denies. It returns
// the matching policy name for logging.
func (e *Engine) MatchFQDNBlock(fqdn string) (bool, string) {
	if fqdn == "" {
		return false, ""
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, cr := range e.rules {
		if cr.effect != types.EffectBlock {
			continue
		}
		if cr.rule.When.Semantic != nil || cr.rule.When.System == nil {
			continue
		}
		sys := cr.rule.When.System
		if sys.Op != "connect" || sys.FQDN == "" {
			continue
		}
		if fqdn == sys.FQDN || strings.HasSuffix(fqdn, "."+sys.FQDN) {
			return true, cr.policyName
		}
	}
	return false, ""
}

// EvaluateSyscall evaluates a pure system-layer event. Rules carrying a semantic
// predicate cannot be judged from a syscall alone and therefore never match here
// (their empty semantic target fails semanticMatch).
func (e *Engine) EvaluateSyscall(ev *types.SyscallEvent, sess *types.AgentSession) types.Decision {
	sys := []sysTarget{{
		op:       mapOp(ev.Operation),
		resource: ev.Resource,
		category: ev.Category,
	}}
	d, _ := e.evalDecision(semTarget{}, sys, sess, ev.Time)
	if sess != nil {
		e.recordMarker(sess.ID, mapOp(ev.Operation), ev.Time)
	}
	return d
}

// EvaluateSemantic evaluates a semantic-layer event (tool_use/MCP/provider/DB).
func (e *Engine) EvaluateSemantic(ev *types.SemanticEvent, sess *types.AgentSession) types.Decision {
	sem := semTarget{
		provider:  ev.Provider,
		mcpMethod: ev.MCPMethod,
	}
	if ev.ToolUse != nil {
		sem.tool = ev.ToolUse.Name
		sem.intentClass = ev.ToolUse.IntentClass
	}

	var sys []sysTarget
	if ev.DBQuery != nil {
		// The parsed query is semantic content (engine/table/op); it matches on the
		// semantic target. The system target carries only the endpoint so a
		// system-layer connect rule on the DB host can still apply.
		sem.db = ev.DBQuery
		sys = append(sys, sysTarget{
			op:       "query",
			resource: ev.DBQuery.Endpoint,
			category: types.CategoryDatabase,
		})
	} else {
		sys = append(sys, sysTarget{})
	}

	d, _ := e.evalDecision(sem, sys, sess, ev.Time)
	if sess != nil && sem.intentClass != "" {
		e.recordMarker(sess.ID, sem.intentClass, ev.Time)
	}
	return d
}

// EvaluateAction evaluates a CorrelatedAction, fusing the semantic intent
// (tool/intentClass/taint) with every reachable system effect. This is where
// intent+system rules fire. If the action is flagged as an intent-effect
// mismatch and the matched rule references intentClass/taint, the verdict is
// escalated to at least Alert.
func (e *Engine) EvaluateAction(a *types.CorrelatedAction, sess *types.AgentSession) types.Decision {
	sem := semTarget{
		tool:        a.ToolName,
		intentClass: a.IntentClass,
		taints:      a.Taint,
	}

	var sys []sysTarget
	for _, ef := range a.Effects {
		sys = append(sys, sysTarget{
			op:       mapOp(ef.Operation),
			resource: ef.Resource,
			category: ef.Category,
		})
	}
	if len(sys) == 0 {
		sys = append(sys, sysTarget{})
	}

	d, cr := e.evalDecision(sem, sys, sess, a.Time)
	if sess != nil && sem.intentClass != "" {
		e.recordMarker(sess.ID, sem.intentClass, a.Time)
	}

	if cr != nil && a.Mismatch && ruleUsesIntent(cr) {
		reason := fmt.Sprintf("intent-effect mismatch on rule %q", cr.ruleName)
		if a.MismatchReason != "" {
			reason += ": " + a.MismatchReason
		}
		if effectRank(d.Effect) < effectRank(types.EffectAlert) {
			d.Effect = types.EffectAlert
			d.Mode = types.EnforcePost
			d.Reason = reason
		} else {
			d.Reason = d.Reason + "; " + reason
		}
	}
	return d
}

// --- core matching -------------------------------------------------------

// semTarget is the semantic-layer view of an input.
type semTarget struct {
	tool        string
	mcpMethod   string
	provider    string
	intentClass string
	taints      []string
	provenance  []string       // file-provenance labels carried by the operand, if any
	db          *types.DBQuery // parsed database query (semantic content off the wire)
}

// sysTarget is one system-layer view of an input (one per reachable effect).
type sysTarget struct {
	op       string
	resource string
	category types.Category
}

// EvaluateProvenance evaluates the rule set against a file's provenance label and
// the operation attempted on that file. The provenance predicate is normally
// discharged in the kernel; this path serves the cases the kernel defers to
// userspace, such as an interpreter reading a script whose argument only userspace
// can resolve. It reports the matching rule so the caller can name the operator's
// policy instead of a literal.
func (e *Engine) EvaluateProvenance(label, op, resource string, sess *types.AgentSession, now time.Time) types.Decision {
	sem := semTarget{provenance: []string{label}}
	sys := []sysTarget{{op: op, resource: resource, category: types.CategoryProcess}}
	d, _ := e.evalDecision(sem, sys, sess, now)
	return d
}

func (e *Engine) evalDecision(sem semTarget, sys []sysTarget, sess *types.AgentSession, now time.Time) (types.Decision, *compiledRule) {
	cr := e.match(sem, sys, sess, now)
	if cr == nil {
		return e.defaultDecision(), nil
	}
	return e.decision(cr, fmt.Sprintf("rule %q matched", cr.ruleName)), cr
}

func (e *Engine) match(sem semTarget, sys []sysTarget, sess *types.AgentSession, now time.Time) *compiledRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	agent := sessionAgent(sess)
	for _, cr := range e.rules {
		if !selectorMatches(cr.selector, agent) {
			continue
		}
		if !semanticMatch(cr, sem) {
			continue
		}
		if !systemMatchAny(cr, sys) {
			continue
		}
		if !e.conditionMatch(cr, sess, now) {
			continue
		}
		return cr
	}
	return nil
}

func (e *Engine) decision(cr *compiledRule, reason string) types.Decision {
	mode := types.EnforcePost
	if cr.effect == types.EffectBlock && cr.rule.When.Semantic == nil {
		mode = types.EnforcePre
	}
	return types.Decision{
		Effect:     cr.effect,
		Mode:       mode,
		PolicyName: cr.policyName,
		Reason:     reason,
		Time:       time.Now().UTC(),
	}
}

func (e *Engine) defaultDecision() types.Decision {
	e.mu.RLock()
	eff := e.defaultEffect
	e.mu.RUnlock()
	if eff == "" {
		eff = types.EffectAllow
	}
	return types.Decision{
		Effect: eff,
		Mode:   types.EnforcePost,
		Reason: "no matching rule; default effect",
		Time:   time.Now().UTC(),
	}
}

// --- predicate matchers --------------------------------------------------

func selectorMatches(sel []string, agent types.AgentKind) bool {
	for _, s := range sel {
		if s == "*" || s == string(agent) {
			return true
		}
	}
	return false
}

func semanticMatch(cr *compiledRule, t semTarget) bool {
	pred := cr.rule.When.Semantic
	if pred == nil {
		return true
	}
	if pred.Tool != "" && !globOrEq(pred.Tool, t.tool) {
		return false
	}
	if pred.MCPMethod != "" && !globOrEq(pred.MCPMethod, t.mcpMethod) {
		return false
	}
	if pred.Provider != "" && !strings.EqualFold(pred.Provider, t.provider) {
		return false
	}
	if pred.IntentClass != "" && !strings.EqualFold(pred.IntentClass, t.intentClass) {
		return false
	}
	if pred.Taint != "" && !containsStr(t.taints, pred.Taint) {
		return false
	}
	// A provenance predicate is normally discharged in the kernel, so most inputs
	// carry no provenance label and such a rule does not match here. It matches
	// only on the paths that hand userspace the label explicitly.
	if pred.Provenance != "" && !containsStr(t.provenance, pred.Provenance) {
		return false
	}
	if pred.DBEngine != "" && (t.db == nil || !strings.EqualFold(t.db.Engine, pred.DBEngine)) {
		return false
	}
	if pred.DBTable != "" && (t.db == nil || !globOrEq(pred.DBTable, t.db.Table)) {
		return false
	}
	if pred.DBOp != "" && (t.db == nil || !strings.EqualFold(t.db.Op, pred.DBOp)) {
		return false
	}
	return true
}

// systemMatchAny returns true if the rule's system predicate is absent, or if it
// matches at least one of the provided system targets.
func systemMatchAny(cr *compiledRule, targets []sysTarget) bool {
	if cr.rule.When.System == nil {
		return true
	}
	for i := range targets {
		if systemMatch(cr, targets[i]) {
			return true
		}
	}
	return false
}

func systemMatch(cr *compiledRule, t sysTarget) bool {
	pred := cr.rule.When.System
	if pred == nil {
		return true
	}
	if pred.Op != "" && pred.Op != t.op {
		return false
	}
	if pred.Path != "" {
		ok, err := path.Match(pred.Path, t.resource)
		if err != nil || !ok {
			return false
		}
	}
	if cr.normDir != "" && !strings.HasPrefix(t.resource, cr.normDir) {
		return false
	}
	if cr.cidr != nil {
		ip := resourceIP(t.resource)
		if ip == nil || !cr.cidr.Contains(ip) {
			return false
		}
	}
	if pred.FQDN != "" && !strings.HasSuffix(t.resource, pred.FQDN) {
		return false
	}
	return true
}

func (e *Engine) conditionMatch(cr *compiledRule, sess *types.AgentSession, now time.Time) bool {
	pred := cr.rule.When.Condition
	if pred == nil {
		return true
	}
	if pred.Coverage != "" {
		if sess == nil || string(sess.Coverage) != pred.Coverage {
			return false
		}
	}
	if pred.SessionState != "" {
		if sess == nil || string(sess.State) != pred.SessionState {
			return false
		}
	}
	if pred.Tampered != nil {
		if sess == nil || sess.Tampered != *pred.Tampered {
			return false
		}
	}
	// Temporal: After requires an earlier marker (an intent class like "read" or a
	// syscall op like "connect") in this session; Within bounds how long ago.
	if pred.After != "" {
		sessID := ""
		if sess != nil {
			sessID = sess.ID
		}
		t, ok := e.markerSeen(sessID, pred.After)
		if !ok {
			return false
		}
		if pred.Within != "" {
			if d, err := time.ParseDuration(pred.Within); err == nil && now.Sub(t) > d {
				return false
			}
		}
	}
	return true
}

// --- helpers -------------------------------------------------------------

func ruleUsesIntent(cr *compiledRule) bool {
	s := cr.rule.When.Semantic
	return s != nil && (s.IntentClass != "" || s.Taint != "")
}

func sessionAgent(sess *types.AgentSession) types.AgentKind {
	if sess == nil {
		return types.AgentUnknown
	}
	return sess.Agent
}

// mapOp maps a SyscallEvent/Effect operation onto the SystemPred.Op vocabulary
// (exec|open|read|write|connect|query). Unknown operations pass through.
func mapOp(operation string) string {
	switch operation {
	case "exec", "execve", "execveat":
		return "exec"
	case "open", "openat", "openat2", "creat":
		return "open"
	case "read", "pread", "pread64", "readv", "preadv", "preadv2":
		return "read"
	case "write", "pwrite", "pwrite64", "writev", "pwritev", "pwritev2":
		return "write"
	case "connect", "sendto", "sendmsg":
		return "connect"
	case "query", "db_query", "db":
		return "query"
	default:
		return operation
	}
}

// normalizeDir ensures a directory predicate ends with a single trailing slash.
func normalizeDir(d string) string {
	if d == "" {
		return d
	}
	if !strings.HasSuffix(d, "/") {
		return d + "/"
	}
	return d
}

// globOrEq reports whether s equals pattern, or matches it as a path.Match glob
// when the pattern contains glob metacharacters.
func globOrEq(pattern, s string) bool {
	if pattern == s {
		return true
	}
	if strings.ContainsAny(pattern, "*?[") {
		ok, err := path.Match(pattern, s)
		return err == nil && ok
	}
	return false
}

func resourceIP(resource string) net.IP {
	host := resource
	if h, _, err := net.SplitHostPort(resource); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func effectRank(e types.PolicyEffect) int {
	switch e {
	case types.EffectAllow:
		return 0
	case types.EffectAudit:
		return 1
	case types.EffectAlert:
		return 2
	case types.EffectBlock:
		return 3
	case types.EffectKill:
		return 4
	default:
		return 0
	}
}

// deriveKernelRules selects the purely system-level Block rules that the
// Enforcer can install pre-operation in the kernel (BPF-LSM): no semantic
// predicate, a system predicate present, an op in {open,read,write,exec}, and a
// Block effect. PathPrefix is taken from Path, falling back to the normalized
// Dir.
func deriveKernelRules(rules []*compiledRule) []pipeline.KernelRule {
	var out []pipeline.KernelRule
	for _, cr := range rules {
		if cr.effect != types.EffectBlock {
			continue
		}
		// A condition (coverage, tampered, after/within) is session or history
		// state that lives in userspace, and the kernel maps carry no place to
		// express it. Installing such a rule would drop the condition and enforce
		// unconditionally, which is strictly more than the operator asked for, so
		// the rule stays with the userspace evaluator instead.
		if cr.rule.When.Condition != nil {
			continue
		}
		// Database query pre-block: a semantic dbTable rule installs the denied
		// table name into the kernel so a matching outbound query is refused
		// pre-operation. This is the push-down of a purely semantic predicate to a
		// kernel decision, so it derives from the semantic layer, not the system one.
		if sem := cr.rule.When.Semantic; sem != nil && sem.DBTable != "" {
			out = append(out, pipeline.KernelRule{
				PolicyName: cr.policyName,
				Selector:   cr.selector,
				Category:   types.CategoryDatabase,
				Operation:  "query",
				DBEngine:   sem.DBEngine,
				DBTable:    sem.DBTable,
				Effect:     cr.effect,
			})
			continue
		}
		if cr.rule.When.Semantic != nil || cr.rule.When.System == nil {
			continue
		}
		sp := cr.rule.When.System
		switch sp.Op {
		case "open", "read", "write", "exec", "delete", "rename", "chmod", "chown":
		case "connect":
			// Network egress pre-block requires a concrete CIDR (installed into
			// the LPM trie); an FQDN-only rule can't be pre-enforced by IP.
			if sp.CIDR == "" {
				continue
			}
		default:
			continue
		}
		prefix := sp.Path
		if prefix == "" {
			prefix = cr.normDir
		}
		out = append(out, pipeline.KernelRule{
			PolicyName: cr.policyName,
			Selector:   cr.selector,
			Category:   kernelCategory(sp.Op),
			Operation:  sp.Op,
			PathPrefix: prefix,
			CIDR:       sp.CIDR,
			Effect:     cr.effect,
		})
	}
	return out
}

func kernelCategory(op string) types.Category {
	switch op {
	case "exec":
		return types.CategoryProcess
	case "connect":
		return types.CategoryNetwork
	default:
		return types.CategoryFile
	}
}
