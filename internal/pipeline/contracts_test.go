// SPDX-License-Identifier: Apache-2.0
// Compile-time checks that each component satisfies its pipeline contract.
package pipeline_test

import (
	"github.com/boanlab/agentknox/internal/correlate"
	"github.com/boanlab/agentknox/internal/export"
	"github.com/boanlab/agentknox/internal/pipeline"
	"github.com/boanlab/agentknox/internal/policy"
	"github.com/boanlab/agentknox/internal/resolver"
	"github.com/boanlab/agentknox/internal/semantic"
	"github.com/boanlab/agentknox/internal/sensor"
	"github.com/boanlab/agentknox/internal/session"
)

var (
	_ pipeline.SystemSensor   = (*sensor.SystemSensor)(nil)
	_ pipeline.SemanticSensor = (*sensor.SemanticSensor)(nil)
	_ pipeline.Resolver       = (*resolver.Resolver)(nil)
	_ pipeline.SemanticParser = (*semantic.Parser)(nil)
	_ pipeline.SessionManager = (*session.Manager)(nil)
	_ pipeline.Correlator     = (*correlate.Engine)(nil)
	_ pipeline.PolicyEngine   = (*policy.Engine)(nil)
	_ pipeline.Exporter       = (*export.Server)(nil)
)
