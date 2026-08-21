package main

import (
	"context"
	"os"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
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

	created, err := c.ContainerCreate(context.Background(), client.ContainerCreateOptions{
		Config:     cfg,
		HostConfig: hostCfg,
		Name:       name,
	})
	if err != nil {
		return "", err
	}

	if _, err = c.ContainerStart(context.Background(), created.ID, client.ContainerStartOptions{}); err != nil {
		_, _ = c.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
		return "", err
	}

	response, err := c.ContainerAttach(context.Background(), created.ID, client.ContainerAttachOptions{
		Stdout: true,
		Stderr: true,
		Logs:   true,
	})
	if err != nil {
		_, _ = c.ContainerRemove(context.Background(), created.ID, client.ContainerRemoveOptions{Force: true})
		return "", err
	}

	go func() {
		defer response.Close()
		response.Reader.WriteTo(os.Stderr)
	}()

	return created.ID, nil
}

func cleanContainer(id string) error {
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer c.Close()

	removeOpts := client.ContainerRemoveOptions{Force: true}
	_, err = c.ContainerRemove(context.Background(), id, removeOpts)
	return err
}
