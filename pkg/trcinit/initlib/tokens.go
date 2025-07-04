package initlib

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/trimble-oss/tierceron-core/v2/core/coreconfig"
	eUtils "github.com/trimble-oss/tierceron/pkg/utils"
	sys "github.com/trimble-oss/tierceron/pkg/vaulthelper/system"
	pb "github.com/trimble-oss/tierceron/trcweb/rpc/apinator"
)

// UploadTokens accepts a file directory and vault object to upload tokens to. Logs to passed logger
func UploadTokens(config *coreconfig.CoreConfig, dir string, tokenFileFiltersSet map[string]bool, v *sys.Vault) []*pb.InitResp_Token {
	tokens := []*pb.InitResp_Token{}
	config.Log.SetPrefix("[TOKEN]")
	config.Log.Printf("Writing tokens from %s\n", dir)
	files, err := os.ReadDir(dir)

	eUtils.LogErrorObject(config, err, true)
	for _, file := range files {
		// Extract and truncate file name
		filename := file.Name()
		ext := filepath.Ext(filename)
		filename = filename[0 : len(filename)-len(ext)]

		if ext == ".yml" || ext == ".yaml" { // Request token from vault
			if len(tokenFileFiltersSet) > 0 {
				found := false
				for tokenFilter, _ := range tokenFileFiltersSet {
					if strings.Contains(file.Name(), tokenFilter) {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			config.Log.Printf("\tFound token file: %s\n", file.Name())
			tokenName, err := v.CreateTokenFromFile(dir + "/" + file.Name())
			eUtils.LogErrorObject(config, err, true)

			if err == nil {
				fmt.Printf("Created token %-30s %s\n", filename+":", tokenName)
				tokens = append(tokens, &pb.InitResp_Token{
					Name:  filename,
					Value: tokenName,
				})
			}
		}

	}
	return tokens
}
