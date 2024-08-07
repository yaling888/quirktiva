package main

import (
	"context"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func startContainer(cfg *container.Config, hostCfg *container.HostConfig, name string) (string, error) {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}
	defer c.Close()

	if !isDarwin {
		hostCfg.NetworkMode = "host"
	}

	containerM, err := c.ContainerCreate(context.Background(), cfg, hostCfg, nil, nil, name)
	if err != nil {
		return "", err
	}

	if err = c.ContainerStart(context.Background(), containerM.ID, container.StartOptions{}); err != nil {
		return "", err
	}

	return containerM.ID, nil
}

func cleanContainer(id string) error {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer c.Close()

	removeOpts := container.RemoveOptions{Force: true}
	return c.ContainerRemove(context.Background(), id, removeOpts)
}
