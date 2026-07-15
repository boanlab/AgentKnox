// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/internal/policy"
	"github.com/boanlab/agentknox/pkg/types"
)

const (
	// dnsMinTTL floors a record's TTL so a hostile resolver cannot force rapid
	// churn by advertising a 0/1-second TTL.
	dnsMinTTL = 30 * time.Second
	// dnsGrace is added past expiry before a resolved IP block is evicted, so a
	// connect immediately following an expiring lookup is still covered.
	dnsGrace = 10 * time.Second
	// dnsSweepInterval is how often expired IP blocks are evicted.
	dnsSweepInterval = 15 * time.Second
)

// dnsGuard turns fqdn policy rules into kernel egress IP blocks. On each observed
// DNS answer whose name matches a Block+connect+fqdn rule, it installs the
// resolved A/AAAA addresses into the enforcer's egress deny map and evicts them
// once their (floored) TTL lapses. It is the userspace half of FQDN enforcement:
// the kernel blocks by IP (socket_connect LSM), and DNS answers keep the IP set
// current.
type dnsGuard struct {
	enforcer pipeline.Enforcer
	policy   *policy.Engine
	log      *zap.Logger

	mu      sync.Mutex
	blocked map[string]time.Time // ip -> expiry
}

func newDNSGuard(enforcer pipeline.Enforcer, pol *policy.Engine, log *zap.Logger) *dnsGuard {
	if log == nil {
		log = zap.NewNop()
	}
	return &dnsGuard{enforcer: enforcer, policy: pol, log: log, blocked: make(map[string]time.Time)}
}

// observe processes a DNS answer, installing egress blocks for resolved IPs when
// the queried name matches an fqdn Block rule.
func (g *dnsGuard) observe(dns *types.DNSInfo) {
	if dns == nil || len(dns.Answers) == 0 {
		return
	}
	blocked, pol := g.policy.MatchFQDNBlock(dns.QName)
	if !blocked {
		return
	}
	for _, a := range dns.Answers {
		ip := net.ParseIP(a.IP)
		if ip == nil {
			continue
		}
		ttl := time.Duration(a.TTL) * time.Second
		if ttl < dnsMinTTL {
			ttl = dnsMinTTL
		}
		exp := time.Now().Add(ttl + dnsGrace)
		g.mu.Lock()
		_, exists := g.blocked[a.IP]
		g.blocked[a.IP] = exp
		g.mu.Unlock()
		if exists {
			continue // already blocked; expiry refreshed above
		}
		if err := g.enforcer.BlockIP(ip); err != nil {
			g.log.Warn("dns: install fqdn egress block failed",
				zap.String("fqdn", dns.QName), zap.String("ip", a.IP), zap.Error(err))
			continue
		}
		g.log.Info("dns: installed fqdn egress block",
			zap.String("policy", pol), zap.String("fqdn", dns.QName), zap.String("ip", a.IP))
	}
}

// sweep runs until ctx is done, evicting expired IP blocks.
func (g *dnsGuard) sweep(ctx context.Context) {
	ticker := time.NewTicker(dnsSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			g.mu.Lock()
			var expired []string
			for ip, exp := range g.blocked {
				if now.After(exp) {
					expired = append(expired, ip)
				}
			}
			for _, ip := range expired {
				delete(g.blocked, ip)
			}
			g.mu.Unlock()
			for _, ip := range expired {
				if parsed := net.ParseIP(ip); parsed != nil {
					_ = g.enforcer.UnblockIP(parsed)
				}
			}
		}
	}
}
