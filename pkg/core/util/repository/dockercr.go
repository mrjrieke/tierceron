package repository

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	eUtils "github.com/trimble-oss/tierceron/pkg/utils"
)

// Return url to the image to be used for download.
func GetImageDownloadUrl(pluginToolConfig map[string]interface{}) (string, error) {
	return "", nil
}

// Defines the keys: "rawImageFile", and "imagesha256" in the map pluginToolConfig.
// TODO: make this scale by streaming image to disk
// (maybe parameterizable so only activated for known larger deployment images)
func GetImageAndShaFromDownload(driverConfig *eUtils.DriverConfig, pluginToolConfig map[string]interface{}) error {
	// TODO: Chewbacca flush out to pull images and download...

	dockerAuth := registry.AuthConfig{
		Username: pluginToolConfig["dockerUser"].(string),
		Password: pluginToolConfig["dockerPassword"].(string),
	}

	cli, err := client.NewClientWithOpts(client.WithHost(pluginToolConfig["dockerRepository"].(string)))
	if err != nil {
		panic(err)
	}
	//ctx := context.Background()
	// token, err := cli.RegistryLogin(ctx, dockerAuth)
	// if err != nil {
	// 	return err
	// }
	// dockerAuth.IdentityToken = token.IdentityToken
	auth, err := registry.EncodeAuthConfig(dockerAuth)

	images, err := cli.ImageList(context.Background(), types.ImageListOptions{})
	if err != nil {
		return err
	}

	opts := &image.PullOptions{
		RegistryAuth: auth,
	}

	for _, image := range images {
		_, err := cli.ImagePull(context.Background(), image.ID, *opts)
		if err != nil {
			return err
		}
	}
	return nil
}

// Pushes image to docker registry from: "rawImageFile", and "pluginname" in the map pluginToolConfig.
func PushImage(driverConfig *eUtils.DriverConfig, pluginToolConfig map[string]interface{}) error {

	cli, err := client.NewClientWithOpts(client.WithHost(pluginToolConfig["dockerRepository"].(string)))
	if err != nil {
		panic(err)
	}

	//
	// 1. Build a local image in docker.
	//
	sha256File := pluginToolConfig["trcsha256"].(string)

	file, fileOpenErr := os.Open(sha256File)
	if fileOpenErr != nil {
		fmt.Println(fileOpenErr.Error())
		return fileOpenErr
	}

	// Close the file when we're done.
	defer file.Close()

	// Create a reader to the file.
	reader := bufio.NewReader(file)
	imageTag := fmt.Sprintf("%s:latest", pluginToolConfig["pluginName"].(string))

	dockerAuth := registry.AuthConfig{
		Username:      pluginToolConfig["dockerUser"].(string),
		Password:      pluginToolConfig["dockerPassword"].(string),
		ServerAddress: pluginToolConfig["dockerRepository"].(string),
	}

	cli.ImageBuild(context.Background(), reader, types.ImageBuildOptions{
		Context:     reader,
		AuthConfigs: map[string]registry.AuthConfig{"config": dockerAuth},
		Dockerfile:  pluginToolConfig["dockerfile"].(string),
		Tags:        []string{imageTag},
	})

	auth, err := registry.EncodeAuthConfig(dockerAuth)
	opts := &image.PushOptions{
		RegistryAuth: auth,
	}

	//
	// 2. Push local image to remote repository indicated by (Maybe not needed since I
	//    build directly on the server?)
	//
	imgCloser, pushErr := cli.ImagePush(context.Background(), imageTag, *opts)
	defer imgCloser.Close()

	return pushErr
}
