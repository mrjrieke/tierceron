package flowsql

import (
	"strconv"
	"strings"

	"github.com/trimble-oss/tierceron/atrium/buildopts/flowcoreopts"
)

func GetDataFlowStatisticInsert(statisticData map[string]interface{}, dbName string, tableName string) map[string]interface{} {
	argosId := statisticData[flowcoreopts.DataflowTestIdColumn].(string)
	argosId = strings.ReplaceAll(argosId, "/", "")
	return GetDataFlowStatisticInsertById(argosId, statisticData, dbName, tableName)
}

func GetDataFlowStatisticInsertById(argosId string, statisticData map[string]interface{}, dbName string, tableName string) map[string]interface{} {
	argosId = strings.ReplaceAll(argosId, "/", "")
	sqlstr := map[string]interface{}{
		"TrcQuery": `INSERT IGNORE INTO ` + dbName + `.` + tableName + `(` + flowcoreopts.DataflowTestNameColumn + `, ` + flowcoreopts.DataflowTestIdColumn + `, flowGroup, mode, stateCode, stateName, timeSplit, lastTestedDate) VALUES ('` +
			statisticData["flowName"].(string) + `','` + argosId + `','` +
			statisticData["flowGroup"].(string) + `','` + strconv.Itoa(statisticData["mode"].(int)) +
			`','` + statisticData["stateCode"].(string) + `','` + statisticData["stateName"].(string) +
			`','` + statisticData["timeSplit"].(string) + `','` + statisticData["lastTestedDate"].(string) + `')` +
			` ON DUPLICATE KEY UPDATE ` +
			flowcoreopts.DataflowTestNameColumn + `= VALUES(` + flowcoreopts.DataflowTestNameColumn + `),` + flowcoreopts.DataflowTestIdColumn + `= VALUES(` + flowcoreopts.DataflowTestIdColumn + `),flowGroup = VALUES(flowGroup),mode = VALUES(mode),stateCode = VALUES(stateCode),stateName = VALUES(stateName),timeSplit = VALUES(timeSplit), lastTestedDate = VALUES(lastTestedDate)`,
		"TrcChangeId": []string{statisticData["flowName"].(string), argosId, statisticData["stateCode"].(string)},
	}
	return sqlstr
}

func GetDataFlowStatisticLM(argosId string, statisticData map[string]interface{}, dbName string, tableName string) map[string]interface{} {
	argosId = strings.ReplaceAll(argosId, "/", "")
	sqlstr := map[string]interface{}{
		"TrcQuery": `select lastTestedDate from ` + dbName + `.` + tableName + ` where ` + flowcoreopts.DataflowTestNameColumn + `='` + statisticData["flowName"].(string) + `' and ` +
			flowcoreopts.DataflowTestIdColumn + "='" + argosId + `' and ` + flowcoreopts.DataflowTestStateCodeColumn + ` = '` + statisticData["stateCode"].(string) + `'`,
	}
	return sqlstr
}

func GetDataFlowStatisticUpdate(statisticData map[string]interface{}, dbName string, tableName string) map[string]interface{} {
	argosId := statisticData[flowcoreopts.DataflowTestIdColumn].(string)
	argosId = strings.ReplaceAll(argosId, "/", "")
	return GetDataFlowStatisticUpdateById(argosId, statisticData, dbName, tableName)
}

func GetDataFlowStatisticUpdateById(argosId string, statisticData map[string]interface{}, dbName string, tableName string) map[string]interface{} {
	argosId = strings.ReplaceAll(argosId, "/", "")
	sqlstr := map[string]interface{}{
		"TrcQuery": `INSERT IGNORE INTO ` + dbName + `.` + tableName + `(` + flowcoreopts.DataflowTestNameColumn + `, ` + flowcoreopts.DataflowTestIdColumn + `, flowGroup, mode, stateCode, stateName, timeSplit, lastTestedDate) VALUES ('` +
			statisticData["flowName"].(string) + `','` + argosId + `','` +
			statisticData["flowGroup"].(string) + `','` + strconv.Itoa(statisticData["mode"].(int)) +
			`','` + statisticData["stateCode"].(string) + `','` + statisticData["stateName"].(string) +
			`','` + statisticData["timeSplit"].(string) + `','` + statisticData["lastTestedDate"].(string) + `')` +
			` ON DUPLICATE KEY UPDATE ` +
			flowcoreopts.DataflowTestNameColumn + `= VALUES(` + flowcoreopts.DataflowTestNameColumn + `),` + flowcoreopts.DataflowTestIdColumn + `= VALUES(` + flowcoreopts.DataflowTestIdColumn + `),flowGroup = VALUES(flowGroup),mode = VALUES(mode),stateCode = VALUES(stateCode),stateName = VALUES(stateName),timeSplit = VALUES(timeSplit), lastTestedDate = VALUES(lastTestedDate)`,
		"TrcChangeId": []string{statisticData["flowName"].(string), argosId, statisticData["stateCode"].(string)},
	}
	return sqlstr
}

func GetDataFlowStatisticsFromArray(dfs []interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	m[flowcoreopts.DataflowTestNameColumn] = dfs[0]
	m[flowcoreopts.DataflowTestIdColumn] = dfs[1]
	m["flowGroup"] = dfs[2]
	m["mode"] = dfs[3]
	m["stateCode"] = dfs[4]
	m["stateName"] = dfs[5]
	m["timeSplit"] = dfs[6]
	m["lastTestedDate"] = dfs[7]
	m["lastModified"] = m["lastTestedDate"] //This is for lastModified comparison -> not used in table or queries
	return m
}

func DataFlowStatisticsSparseArrayToMap(dfs []interface{}) map[string]interface{} {
	m := make(map[string]interface{})
	m["lastModified"] = dfs[0] //This is for lastModified comparison -> not used in table or queries
	return m
}

func GetDataFlowStatisticFilterFieldFromConfig(tableConfig interface{}) string {
	// Not pulling or pushing to remote
	// dfsNode := tableConfig.(*core.TTDINode)
	return "" //dfsNode.Name
}
