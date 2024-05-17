// Copyright (c) 2024 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	cdhgrpcapi "github.com/confidential-containers/guest-components/confidential-data-hub/golang/pkg/api/cdhgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	CDHGrpcSocket      = "127.0.0.1:8043"
	SealedSecretPrefix = "sealed."
)

type cdhGrpcClient struct {
	conn               *grpc.ClientConn
	sealedSecretClient cdhgrpcapi.SealedSecretServiceClient
}

func CreateCDHGrpcClient(sockAddress string) (*cdhGrpcClient, error) {
	conn, err := grpc.Dial(sockAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to cdh sock %q: %w", sockAddress, err)
	}

	sealedSecretClient := cdhgrpcapi.NewSealedSecretServiceClient(conn)

	c := &cdhGrpcClient{
		conn:               conn,
		sealedSecretClient: sealedSecretClient,
	}
	return c, nil
}

func (c *cdhGrpcClient) Close() error {
	return c.conn.Close()
}

func (c *cdhGrpcClient) unsealSecret(ctx context.Context, secret string) (string, error) {
	input := cdhgrpcapi.UnsealSecretInput{Secret: []byte(secret)}
	output, err := c.sealedSecretClient.UnsealSecret(ctx, &input)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret: %w", err)
	}

	return string(output.GetPlaintext()[:]), nil
}

func (c *cdhGrpcClient) UnsealEnv(ctx context.Context, env string) (string, error) {
	unsealedValue, err := c.unsealSecret(ctx, env)
	if err != nil {
		return "", fmt.Errorf("failed to unseal secret from env, err: %w", err)
	}
	return unsealedValue, nil
}

func (c *cdhGrpcClient) UnsealFile(ctx context.Context, sealedFile string) (string, error) {
	fileInfo, err := os.Stat(sealedFile)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("sealed File %s does not exist", sealedFile)
	}
	if !fileInfo.Mode().IsRegular() {
		return "", fmt.Errorf("sealed File %s is not a regular file", sealedFile)
	}
	contents, err := os.ReadFile(sealedFile)
	if err != nil {
		return "", fmt.Errorf("sealed File %s is failed to read, err = %w", sealedFile, err)
	}

	if strings.HasPrefix(string(contents), SealedSecretPrefix) {
		unsealedValue, err := c.unsealSecret(ctx, string(contents))
		if err != nil {
			return "", fmt.Errorf("failed to unseal secret from file, err: %w", err)
		}
		return unsealedValue, nil
	} else {
		return "", fmt.Errorf("sealed File %s is not a sealed secret", sealedFile)
	}
}