package core

import (
	"sync"
	"tierceron/trcvault/util"
	"tierceron/trcx/db"
	"tierceron/trcx/extract"

	eUtils "tierceron/utils"
)

var changesLock sync.Mutex

func getChangeIdQuery(databaseName string, changeTable string) string {
	return "SELECT id FROM " + databaseName + `.` + changeTable
}

func getDeleteChangeQuery(databaseName string, changeTable string, id string) string {
	return "DELETE FROM " + databaseName + `.` + changeTable + " WHERE id = '" + id + "'"
}

func getInsertChangeQuery(databaseName string, changeTable string, id string) string {
	return `INSERT IGNORE INTO ` + databaseName + `.` + changeTable + `VALUES (` + id + `, current_timestamp());`
}

func (tfmContext *TrcFlowMachineContext) seedVaultFromChanges(
	tfContext *TrcFlowContext,
	identityColumnName string,
	vaultIndexColumnName string,
	isInit bool,
	getIndexedPathExt func(engine interface{}, rowDataMap map[string]interface{}, vaultIndexColumnName string, databaseName string, tableName string, dbCallBack func(interface{}, string) (string, []string, [][]string, error)) (string, error),
	flowPushRemote func(map[string]interface{}, map[string]interface{}) error) error {

	var matrixChangedEntries [][]string
	var changedEntriesQuery string

	changesLock.Lock()

	/*if isInit {
		changedEntriesQuery = `SELECT ` + identityColumnName + ` FROM ` + databaseName + `.` + tableName
	} else { */
	changedEntriesQuery = getChangeIdQuery(tfContext.FlowSourceAlias, tfContext.ChangeFlowName)
	//}

	_, _, matrixChangedEntries, err := db.Query(tfmContext.TierceronEngine, changedEntriesQuery)
	if err != nil {
		eUtils.LogErrorObject(tfmContext.Config, err, false)
	}
	for _, changedEntry := range matrixChangedEntries {
		changedId := changedEntry[0]
		_, _, _, err = db.Query(tfmContext.TierceronEngine, getDeleteChangeQuery(tfContext.FlowSourceAlias, tfContext.ChangeFlowName, changedId))
		if err != nil {
			eUtils.LogErrorObject(tfmContext.Config, err, false)
		}
	}
	changesLock.Unlock()

	for _, changedEntry := range matrixChangedEntries {
		changedId := changedEntry[0]

		changedTableQuery := `SELECT * FROM ` + tfContext.FlowSourceAlias + `.` + tfContext.Flow.TableName() + ` WHERE ` + identityColumnName + `='` + changedId + `'` // TODO: Implement query using changedId

		_, changedTableColumns, changedTableRowData, err := db.Query(tfmContext.TierceronEngine, changedTableQuery)
		if err != nil {
			eUtils.LogErrorObject(tfmContext.Config, err, false)
			continue
		}

		rowDataMap := map[string]interface{}{}
		for i, column := range changedTableColumns {
			rowDataMap[column] = changedTableRowData[0][i]
		}
		// Convert matrix/slice to tenantConfiguration map
		// Columns are keys, values in tenantData

		//Use trigger to make another table
		//Check for tenantId

		indexPath, indexPathErr := getIndexedPathExt(tfmContext.TierceronEngine, rowDataMap, vaultIndexColumnName, tfContext.FlowSourceAlias, tfContext.Flow.TableName(), func(engine interface{}, query string) (string, []string, [][]string, error) {
			return db.Query(engine.(*db.TierceronEngine), query)
		})
		if indexPathErr != nil {
			eUtils.LogErrorObject(tfmContext.Config, indexPathErr, false)
			// Re-inject into changes because it might not be here yet...
			_, _, _, err = db.Query(tfmContext.TierceronEngine, getInsertChangeQuery(tfContext.FlowSourceAlias, tfContext.ChangeFlowName, changedId))
			if err != nil {
				eUtils.LogErrorObject(tfmContext.Config, err, false)
			}
			continue
		}

		// TODO: This should be simplified to lib.GetIndexedPathExt() -- replace above
		seedError := util.SeedVaultById(tfmContext.Config, tfContext.GoMod, tfContext.Flow.ServiceName(), tfmContext.Config.VaultAddress, tfContext.Vault.GetToken(), tfContext.FlowData.(*extract.TemplateResultData), rowDataMap, indexPath, tfContext.FlowSource)
		if seedError != nil {
			eUtils.LogErrorObject(tfmContext.Config, seedError, false)
			// Re-inject into changes because it might not be here yet...
			_, _, _, err = db.Query(tfmContext.TierceronEngine, getInsertChangeQuery(tfContext.FlowSourceAlias, tfContext.ChangeFlowName, changedId))
			if err != nil {
				eUtils.LogErrorObject(tfmContext.Config, err, false)
			}
			continue
		}

		// Push this change to the flow for delivery to remote data source.
		if !isInit {
			pushError := flowPushRemote(tfContext.RemoteDataSource, rowDataMap)
			if pushError != nil {
				eUtils.LogErrorObject(tfmContext.Config, err, false)
			}
		}

	}

	return nil
}

func (tfmContext *TrcFlowMachineContext) seedTrcDbFromChanges(
	tfContext *TrcFlowContext,
	identityColumnName string,
	vaultIndexColumnName string,
	isInit bool,
	getIndexedPathExt func(engine interface{}, rowDataMap map[string]interface{}, vaultIndexColumnName string, databaseName string, tableName string, dbCallBack func(interface{}, string) (string, []string, [][]string, error)) (string, error),
	flowPushRemote func(map[string]interface{}, map[string]interface{}) error) error {

	// TODO: Implement...
	// Might be able to leverage some of the code from seedVaultFromChanges

	return nil
}
