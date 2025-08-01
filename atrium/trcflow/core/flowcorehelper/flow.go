package flowcorehelper

//import "github.com/trimble-oss/tierceron/buildopts/flowopts"
import (
	flowcore "github.com/trimble-oss/tierceron-core/v2/flow"
)

type FlowStateUpdate struct {
	FlowName    string
	StateUpdate string
	SyncFilter  string
	SyncMode    string
	FlowAlias   string
}

type CurrentFlowState struct {
	State      int64
	SyncMode   string
	SyncFilter string
	FlowAlias  string
}

func UpdateTierceronFlowState(tfmContext flowcore.FlowMachineContext, flowName string, newState string, syncFilter string, syncMode string, flowAlias string) map[string]any {
	return map[string]any{
		"TrcQuery":    "update " + tfmContext.GetDatabaseName(flowcore.TrcFlumeDb) + "." + flowcore.TierceronControllerFlow.TableName() + " set lastModified=current_timestamp(), syncMode='" + syncMode + "', state=" + newState + ", SyncFilter='" + syncFilter + "', flowAlias='" + flowAlias + "' where flowName='" + flowName + "'",
		"TrcChangeId": flowName,
	}
}

func SyncCheck(syncMode string) string {
	switch syncMode {
	case "nosync":
		return " with no syncing"
	case "push":
		return " with push sync"
	case "pull":
		return " with pull sync"
	case "pullonce":
		return " to pull once"
	case "pushonce":
		return " to push once"
	case "pullsynccomplete":
		return " - Pull synccomplete..waiting for new syncMode value"
	case "pullcomplete":
		return " - Pull complete..waiting for new syncMode value"
	case "pushcomplete":
		return " - Push complete..waiting for new syncMode value"
	case "pusherror":
		return " - Push error..waiting for new syncMode value"
	case "pullerror":
		return " - Pull error..waiting for new syncMode value"
	default:
		return "...waiting for new syncMode value"
	}
}
