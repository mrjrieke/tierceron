package flowopts

import (
	flowcore "github.com/trimble-oss/tierceron-core/v2/flow"
	trcflowcore "github.com/trimble-oss/tierceron/atrium/trcflow/core"
)

type Option func(*OptionsBuilder)

type OptionsBuilder struct {
	// Flow
	AllowTrcdbInterfaceOverride func() bool
	GetAdditionalFlows          func() []flowcore.FlowDefinition
	GetAdditionalTestFlows      func() []flowcore.FlowDefinition
	GetAdditionalFlowsByState   func(string) []flowcore.FlowDefinition
	ProcessTestFlowController   func(tfmContext flowcore.FlowMachineContext, tfContext flowcore.FlowContext) error
	ProcessFlowController       func(tfmContext flowcore.FlowMachineContext, tfContext flowcore.FlowContext) error
	GetFlowMachineTemplates     func() map[string]any
	ProcessAskFlumeEventMapper  func(askFlumeContext *trcflowcore.AskFlumeContext, query *trcflowcore.AskFlumeMessage, tfmContext *trcflowcore.TrcFlowMachineContext, tfContext *trcflowcore.TrcFlowContext) *trcflowcore.AskFlumeMessage
}

func LoadOptions() Option {
	return func(optionsBuilder *OptionsBuilder) {
		optionsBuilder.AllowTrcdbInterfaceOverride = AllowTrcdbInterfaceOverride
		optionsBuilder.GetAdditionalFlows = GetAdditionalFlows
		optionsBuilder.GetAdditionalTestFlows = GetAdditionalTestFlows
		optionsBuilder.GetAdditionalFlowsByState = GetAdditionalFlowsByState
		optionsBuilder.ProcessTestFlowController = ProcessTestFlowController
		optionsBuilder.ProcessFlowController = ProcessFlowController
		optionsBuilder.GetFlowMachineTemplates = GetFlowMachineTemplates
		optionsBuilder.ProcessAskFlumeEventMapper = ProcessAskFlumeEventMapper
	}
}

var BuildOptions *OptionsBuilder

func NewOptionsBuilder(opts ...Option) {
	BuildOptions = &OptionsBuilder{}
	for _, opt := range opts {
		opt(BuildOptions)
	}
}
