package initlib

import (
	"bitbucket.org/dexterchaney/whoville/utils"
	"bitbucket.org/dexterchaney/whoville/vault-helper/kv"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func UploadTemplateDirectory(mod *kv.Modifier, dirName string) (error, []string) {

	dirs, err := ioutil.ReadDir(dirName)
	if err != nil {
		return err, nil
	}

	// Parse each subdirectory as a service name
	for _, subDir := range dirs {
		if subDir.IsDir() {
			pathName := dirName + "/" + subDir.Name()
			err, warn := UploadTemplates(mod, pathName)
			if err != nil || len(warn) > 0 {
				return err, warn
			}
		}
	}
	return nil, nil
}

func UploadTemplates(mod *kv.Modifier, dirName string) (error, []string) {
	// Open directory
	files, err := ioutil.ReadDir(dirName)
	if err != nil {
		return err, nil
	}

	// Use name of containing directory as the template subdirectory
	splitDir := strings.SplitAfter(dirName, "/")
	subDir := splitDir[len(splitDir)-1]

	// Parse through files
	for _, file := range files {
		// Extract extension and name
		ext := filepath.Ext(file.Name())
		name := file.Name()
		name = name[0 : len(name)-len(ext)] // Truncate extension

		if ext == ".tmpl" { // Only upload template files
			fmt.Printf("Found template file %s\n", file.Name())
			// Seperate name and extension one more time for saving to vault
			ext = filepath.Ext(name)
			name = name[0 : len(name)-len(ext)]

			// Extract values
			extractedValues, err := utils.Parse(dirName+"/"+file.Name(), subDir, name)
			if err != nil {
				return err, nil
			}

			// Open file
			f, err := os.Open(dirName + "/" + file.Name())
			if err != nil {
				return err, nil
			}

			// Read the file
			fileBytes := make([]byte, file.Size())
			_, err = f.Read(fileBytes)
			if err != nil {
				return err, nil
			}

			// Construct template path for vault
			templatePath := "templates/" + subDir + "/" + name + "/template-file"
			fmt.Printf("\tUploading template to path:\t%s\n", templatePath)

			// Construct value path for vault
			valuePath := "values/" + subDir + "/" + name
			fmt.Printf("\tUploading values to path:\t%s\n", valuePath)

			// Write templates to vault and output errors/warnings
			warn, err := mod.Write(templatePath, map[string]interface{}{"data": fileBytes, "ext": ext})
			if err != nil || len(warn) > 0 {
				return err, warn
			}

			// Write values to vault and output any errors/warnings
			warn, err = mod.Write(valuePath, extractedValues)
			if err != nil || len(warn) > 0 {
				return err, warn
			}
		}
	}
	return nil, nil
}