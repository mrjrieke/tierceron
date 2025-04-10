package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v2"

	hcore "github.com/trimble-oss/tierceron/atrium/vestibulum/hive/plugins/trcvico/hcore"
	// Update package path as needed
)

func GetConfigPaths(pluginName string) []string {
	return hcore.GetConfigPaths(pluginName)
}

func Init(pluginName string, properties *map[string]interface{}) {
	hcore.Init(pluginName, properties)
}

func main() {
	logFilePtr := flag.String("log", "./trcvico.log", "Output path for log file")
	flag.Parse()
	config := make(map[string]interface{})

	f, err := os.OpenFile(*logFilePtr, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		os.Exit(-1)
	}
	logger := log.New(f, "[trcvico]", log.LstdFlags)
	config["log"] = logger

	data, err := os.ReadFile("config.yml")
	if err != nil {
		logger.Println("Error reading YAML file:", err)
		os.Exit(-1)
	}

	// Create an empty map for the YAML data
	var configCommon map[string]interface{}

	// Unmarshal the YAML data into the map
	err = yaml.Unmarshal(data, &configCommon)
	if err != nil {
		logger.Println("Error unmarshaling YAML:", err)
		os.Exit(-1)
	}
	config[hcore.COMMON_PATH] = &configCommon

	Init("vico", &config)
	hcore.GetConfigContext("vico").Start("vico")
}
