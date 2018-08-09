package main

import "C"

import (
	"strings"

	"bitbucket.org/dexterchaney/whoville/vault-helper/kv"
	"bitbucket.org/dexterchaney/whoville/vaultconfig/utils"
)

//export ConfigTemplateLib
func ConfigTemplateLib(token string, address string, env string, templatePath string, configuredFilePath string, secretMode bool, servicesWanted string) string {

	services := []string{}
	if servicesWanted != "" {
		services = strings.Split(servicesWanted, ",")
	}

	for _, service := range services {
		service = strings.TrimSpace(service)
	}

	mod, err := kv.NewModifier(token, address)
	mod.Env = env
	if err != nil {
		panic(err)
	}
	return utils.ConfigTemplate(mod, templatePath, configuredFilePath, secretMode, services...)
}
func main() {}
