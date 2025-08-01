package db

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/trimble-oss/tierceron/pkg/utils/config"

	bitcore "github.com/trimble-oss/tierceron-core/v2/bitlock"
	"github.com/trimble-oss/tierceron/atrium/trcdb/engine"
	eUtils "github.com/trimble-oss/tierceron/pkg/utils"
	helperkv "github.com/trimble-oss/tierceron/pkg/vaulthelper/kv"

	sqle "github.com/dolthub/go-mysql-server"
	sqlememory "github.com/dolthub/go-mysql-server/memory"
	"github.com/dolthub/go-mysql-server/sql"
	"github.com/dolthub/go-mysql-server/sql/mysql_db"

	sqles "github.com/dolthub/go-mysql-server/sql"
)

var m sync.Mutex

// CreateEngine - creates a Tierceron query engine for query of configurations.
func CreateEngine(driverConfig *config.DriverConfig,
	templatePaths []string, env string, dbname string) (*engine.TierceronEngine, error) {

	te := &engine.TierceronEngine{Database: sqlememory.NewDatabase(dbname), Engine: nil, TableCache: map[string]*engine.TierceronTable{}, Context: sqles.NewEmptyContext(), Config: *driverConfig}

	var goMod *helperkv.Modifier
	tokenNamePtr := driverConfig.CoreConfig.GetCurrentToken("config_token_%s")
	goMod, errModInit := helperkv.NewModifierFromCoreConfig(driverConfig.CoreConfig, *tokenNamePtr, driverConfig.CoreConfig.Env, false)
	if errModInit != nil {
		return nil, errModInit
	}
	goMod.Env = env
	/*	This is for versioning - used below
		projectServiceMap, err := goMod.GetProjectServicesMap()
		if err != nil {
			return nil, err
		}
	*/

	var envEnterprises []string
	goMod.Env = ""
	tempEnterprises, err := goMod.List("values", driverConfig.CoreConfig.Log)
	if err != nil {
		eUtils.LogErrorObject(driverConfig.CoreConfig, err, false)
		return nil, err
	}
	if tempEnterprises != nil {
		for _, enterprise := range tempEnterprises.Data["keys"].([]any) {
			envEnterprises = append(envEnterprises, strings.Replace(enterprise.(string), "/", "", 1))
		}
		/* This is for versioning -> enhancements might be needed
			// Fun stuff here....
			var versionMetadata []string
			var wgEnterprise sync.WaitGroup
			// Load all vault table data into tierceron sql engine.
			for _, envEnterprise := range envEnterprises {
				wgEnterprise.Add(1)
				go func(driverConfig *config.DriverConfig, enterpriseEnv string) {
					defer wgEnterprise.Done()
					if !strings.Contains(enterpriseEnv, ".") {
						return
					}

					tableMod, _, err := eUtils.InitVaultMod(config)
					if err != nil {
						eUtils.LogErrorMessage("Could not access vault.  Failure to start.", config.Log, false)
						return
					}

					tableMod.Env = ""
					versionMetadata = versionMetadata[:0]
					fileMetadata, err := tableMod.GetVersionValues(tableMod, config.WantCerts, "values/"+enterpriseEnv, config.Log)
					if fileMetadata == nil {
						return
					}
					if err != nil {
						eUtils.LogErrorObject(err, config.Log, false)
						return
					}

					var first map[string]any
					for _, file := range fileMetadata {
						if first == nil {
							first = file
							break
						}
					}

					for versionNumber, _ := range first {
						versionMetadata = append(versionMetadata, versionNumber)
					}

					for _, versionNo := range versionMetadata {
						for project, services := range projectServiceMap {
							// TODO: optimize this for scale.
							for _, service := range services {
								for _, filter := range config.VersionFilter {
									if filter == service {
										TransformConfig(tableMod, te, enterpriseEnv, versionNo, project, service, config)
									}
								}
							}
						}
					}
				}(config, envEnterprise)
			}
			wgEnterprise.Wait()
		}
		*/
		te.Engine = sqle.NewDefault(sqlememory.NewMemoryDBProvider(te.Database))
		te.Engine.Analyzer.Debug = false
		te.Engine.Analyzer.Catalog.MySQLDb.SetPersister(&mysql_db.NoopPersister{})
	}
	if goMod != nil {
		goMod.Release()
	}

	return te, nil
}

// Query - queries configurations using standard ANSI SQL syntax.
// Example: select * from ServiceTechMobileAPI.configfile
func Query(te *engine.TierceronEngine, query string, queryLock *sync.Mutex) (string, []string, [][]any, error) {
	// Create a test memory database and register it to the default engine.

	if strings.Contains(query, "%s.") {
		query = fmt.Sprintf(query, te.Database.Name())
	}
	//ctx := sql.NewContext(context.Background(), sql.WithIndexRegistry(sql.NewIndexRegistry()), sql.WithViewRegistry(sql.NewViewRegistry())).WithCurrentDB(te.Database.Name())
	//ctx := sql.NewContext(context.Background()).WithCurrentDB(te.Database.Name())
	ctx := sqles.NewContext(context.Background())
	ctx.WithQuery(query)
	queryLock.Lock()
	//	te.Context = ctx
	schema, r, err := te.Engine.Query(ctx, query)
	queryLock.Unlock()
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return "", nil, nil, errors.New("Duplicate primary key found.")
		}
		return "", nil, nil, err
	}

	columns := []string{}
	matrix := [][]any{}
	tableName := ""

	for _, col := range schema {
		if tableName == "" {
			tableName = col.Source
		}

		columns = append(columns, col.Name)
	}

	if len(columns) > 0 {
		// Iterate results and print them.
		okResult := false
		for {
			queryLock.Lock()
			row, err := r.Next(ctx)
			queryLock.Unlock()
			if err == io.EOF {
				break
			} else if err != nil {
				return "", nil, nil, err
			}
			rowData := []any{}
			if sqles.IsOkResult(row) { //This is for insert statements
				okResult = true
				sqlOkResult := sqles.GetOkResult(row)
				if sqlOkResult.RowsAffected > 0 {
					matrix = append(matrix, rowData)
				} else {
					if sqlOkResult.InsertID > 0 {
						rowData = append(rowData, sqlOkResult.InsertID)
						matrix = append(matrix, rowData)
					}
				}
			} else {
				for _, col := range row {
					rowData = append(rowData, col)
				}
				matrix = append(matrix, rowData)
			}
		}
		if okResult {
			return "ok", nil, matrix, nil
		}
	}

	return tableName, columns, matrix, nil
}

// Query - queries configurations using standard ANSI SQL syntax.
// Able to run query with multiple flows
// Example: select * from ServiceTechMobileAPI.configfile
func QueryN(te *engine.TierceronEngine, query string, queryID uint64, bitlock bitcore.BitLock) (string, []string, [][]any, error) {
	// Create a test memory database and register it to the default engine.

	for _, literal := range []string{"from %s.", "FROM %s.", "join %s.", "JOIN %s."} {
		if strings.Contains(query, literal) {
			query = strings.ReplaceAll(query, literal, fmt.Sprintf(literal, te.Database.Name()))
		}
	}
	//ctx := sql.NewContext(context.Background(), sql.WithIndexRegistry(sql.NewIndexRegistry()), sql.WithViewRegistry(sql.NewViewRegistry())).WithCurrentDB(te.Database.Name())
	//ctx := sql.NewContext(context.Background()).WithCurrentDB(te.Database.Name())
	ctx := sqles.NewContext(context.Background())
	ctx.WithQuery(query)
	bitlock.Lock(queryID)
	//	te.Context = ctx
	schema, r, err := te.Engine.Query(ctx, query)
	bitlock.Unlock(queryID)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return "", nil, nil, errors.New("Duplicate primary key found.")
		}
		return "", nil, nil, err
	}

	columns := []string{}
	matrix := [][]any{}
	tableName := ""

	for _, col := range schema {
		if tableName == "" {
			tableName = col.Source
		}

		columns = append(columns, col.Name)
	}

	if len(columns) > 0 {
		// Iterate results and print them.
		okResult := false
		for {
			bitlock.Lock(queryID)
			row, err := r.Next(ctx)
			bitlock.Unlock(queryID)
			if err == io.EOF {
				break
			} else if err != nil {
				return "", nil, nil, err
			}
			rowData := []any{}
			if sqles.IsOkResult(row) { //This is for insert statements
				okResult = true
				sqlOkResult := sqles.GetOkResult(row)
				if sqlOkResult.RowsAffected > 0 {
					matrix = append(matrix, rowData)
				} else {
					if sqlOkResult.InsertID > 0 {
						rowData = append(rowData, sqlOkResult.InsertID)
						matrix = append(matrix, rowData)
					}
				}
			} else {
				for _, col := range row {
					rowData = append(rowData, col)
				}
				matrix = append(matrix, rowData)
			}
		}
		if okResult {
			return "ok", nil, matrix, nil
		}
	}

	return tableName, columns, matrix, nil
}

// Query - queries configurations using standard ANSI SQL syntax.
// Example: select * from ServiceTechMobileAPI.configfile
func QueryWithBindings(te *engine.TierceronEngine, query string, bindings map[string]sqles.Expression, queryLock *sync.Mutex) (string, []string, [][]any, error) {
	// Create a test memory database and register it to the default engine.

	//ctx := sql.NewContext(context.Background(), sql.WithIndexRegistry(sql.NewIndexRegistry()), sql.WithViewRegistry(sql.NewViewRegistry())).WithCurrentDB(te.Database.Name())
	//ctx := sql.NewContext(context.Background()).WithCurrentDB(te.Database.Name())
	ctx := sql.NewContext(context.Background())
	ctx.WithQuery(query)
	queryLock.Lock()
	//	te.Context = ctx
	schema, r, queryErr := te.Engine.QueryWithBindings(ctx, query, bindings)
	queryLock.Unlock()
	if queryErr != nil {
		if strings.Contains(queryErr.Error(), "duplicate") {
			return "", nil, nil, errors.New("Duplicate primary key found.")
		}
		return "", nil, nil, queryErr
	}

	columns := []string{}
	matrix := [][]any{}
	tableName := ""

	for _, col := range schema {
		if tableName == "" {
			tableName = col.Source
		}

		columns = append(columns, col.Name)
	}

	if len(columns) > 0 {
		// Iterate results and print them.
		okResult := false
		for {
			queryLock.Lock()
			row, err := r.Next(ctx)
			queryLock.Unlock()
			if err == io.EOF {
				break
			}
			rowData := []any{}
			if sqles.IsOkResult(row) { //This is for insert statements
				okResult = true
				sqlOkResult := sqles.GetOkResult(row)
				if sqlOkResult.RowsAffected > 0 {
					matrix = append(matrix, rowData)
				} else {
					if sqlOkResult.InsertID > 0 {
						rowData = append(rowData, sqlOkResult.InsertID)
						matrix = append(matrix, rowData)
					}
				}
			} else {
				for _, col := range row {
					rowData = append(rowData, col.(string))
				}
				matrix = append(matrix, rowData)
			}
		}
		if okResult {
			return "ok", nil, matrix, nil
		}
	}

	return tableName, columns, matrix, nil
}

// Query - queries configurations using standard ANSI SQL syntax.
// Able to run query with multiple flows with bindings.
// Example: select * from ServiceTechMobileAPI.configfile
func QueryWithBindingsN(te *engine.TierceronEngine, query string, bindings map[string]sqles.Expression, queryID uint64, bitlock bitcore.BitLock) (string, []string, [][]any, error) {
	// Create a test memory database and register it to the default engine.

	//ctx := sql.NewContext(context.Background(), sql.WithIndexRegistry(sql.NewIndexRegistry()), sql.WithViewRegistry(sql.NewViewRegistry())).WithCurrentDB(te.Database.Name())
	//ctx := sql.NewContext(context.Background()).WithCurrentDB(te.Database.Name())
	ctx := sql.NewContext(context.Background())
	ctx.WithQuery(query)
	bitlock.Lock(queryID)
	//	te.Context = ctx
	schema, r, queryErr := te.Engine.QueryWithBindings(ctx, query, bindings)
	bitlock.Unlock(queryID)
	if queryErr != nil {
		if strings.Contains(queryErr.Error(), "duplicate") {
			return "", nil, nil, errors.New("Duplicate primary key found.")
		}
		return "", nil, nil, queryErr
	}

	columns := []string{}
	matrix := [][]any{}
	tableName := ""

	for _, col := range schema {
		if tableName == "" {
			tableName = col.Source
		}

		columns = append(columns, col.Name)
	}

	if len(columns) > 0 {
		// Iterate results and print them.
		okResult := false
		for {
			bitlock.Lock(queryID)
			row, err := r.Next(ctx)
			bitlock.Unlock(queryID)
			if err == io.EOF {
				break
			}
			rowData := []any{}
			if sqles.IsOkResult(row) { //This is for insert statements
				okResult = true
				sqlOkResult := sqles.GetOkResult(row)
				if sqlOkResult.RowsAffected > 0 {
					matrix = append(matrix, rowData)
				} else {
					if sqlOkResult.InsertID > 0 {
						rowData = append(rowData, sqlOkResult.InsertID)
						matrix = append(matrix, rowData)
					}
				}
			} else {
				for _, col := range row {
					rowData = append(rowData, col.(string))
				}
				matrix = append(matrix, rowData)
			}
		}
		if okResult {
			return "ok", nil, matrix, nil
		}
	}

	return tableName, columns, matrix, nil
}
