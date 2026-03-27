package main

import (
	"context"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

func startContainer(cfg *container.Config, hostCfg *container.HostConfig, name string) (string, error) {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return "", err
	}
	defer c.Close()

	if !isDarwin {
		hostCfg.NetworkMode = "host"
	}

	createOptions := client.ContainerCreateOptions{
		Config:     cfg,
		HostConfig: hostCfg,
		Name:       name,
	}
	containerM, err := c.ContainerCreate(context.Background(), createOptions)
	if err != nil {
		return "", err
	}

	if _, err = c.ContainerStart(context.Background(), containerM.ID, client.ContainerStartOptions{}); err != nil {
		return "", err
	}

	return containerM.ID, nil
}

func cleanContainer(id string) error {
	c, err := client.New(client.FromEnv)
	if err != nil {
		return err
	}
	defer c.Close()

	removeOpts := client.ContainerRemoveOptions{Force: true}
	_, err = c.ContainerRemove(context.Background(), id, removeOpts)
	return err
}
