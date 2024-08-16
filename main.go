package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/day0ops/istio-authz/authz-server/pkg/config"
	"github.com/day0ops/istio-authz/authz-server/pkg/logger"
	"github.com/golang-jwt/jwt"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	az "github.com/day0ops/istio-authz/authz-server/pkg/authz"
	hc "github.com/day0ops/istio-authz/authz-server/pkg/healthz"
	auth "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

var (
	port = flag.Int("port", config.DefaultPort, "gRPC port")
)

func main() {
	os.Exit(start())
}

func start() int {
	l := logger.Get()

	flag.Parse()

	if *port <= 0 {
		l.Error("invalid port specified")
		flag.Usage()
		return 2
	}

	maxStreams := config.DefaultMaxStreams
	if config.MaxConcurrentStreams != "" {
		s, err := strconv.ParseUint(config.MaxConcurrentStreams, 10, 32)
		if err != nil {
			l.Error("unable to read MAX_CONCURRENT_STREAMS var", zap.Error(err))
			return 1
		}
		maxStreams = uint32(s)
	}

	keyFile := config.DefaultKeyfile
	if config.PrivateKeyFile != "" {
		keyFile = config.PrivateKeyFile
	}
	pvtKeyData, err := os.ReadFile(keyFile)
	if err != nil {
		l.Error(fmt.Sprintf("failed to read key file: %s", keyFile), zap.Error(err))
		return 1
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(pvtKeyData)
	if err != nil {
		l.Error(fmt.Sprintf("failed to parse key file: %s", keyFile), zap.Error(err))
		return 1
	}

	pubFile := config.DefaultVerifyfile
	if config.PubVerifyeKeyFile != "" {
		pubFile = config.PubVerifyeKeyFile
	}
	pubKeyData, err := os.ReadFile(pubFile)
	if err != nil {
		l.Error(fmt.Sprintf("failed to read verify file: %s", keyFile), zap.Error(err))
		return 1
	}

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKeyData)
	if err != nil {
		l.Error(fmt.Sprintf("failed to parse verify file: %s", keyFile), zap.Error(err))
		return 1
	}

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		l.Error(fmt.Sprintf("failed to listen to port %d", *port), zap.Error(err))
		return 1
	}

	opts := []grpc.ServerOption{grpc.MaxConcurrentStreams(maxStreams)}
	opts = append(opts)

	s := grpc.NewServer(opts...)

	auth.RegisterAuthorizationServer(s, &az.AuthorizationServer{Log: l, PrivateKey: privateKey, PublicKey: verifyKey})
	healthpb.RegisterHealthServer(s, &hc.HealthServer{})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		l.Info("starting gRPC server on port", zap.Int("port", *port))
		if err := s.Serve(lis); err != nil {
			l.Info("error starting server", zap.Error(err))
			return err
		}
		return nil
	})

	<-ctx.Done()

	eg.Go(func() error {
		l.Info("gracefully stopping gRPC server")
		s.GracefulStop()
		return nil
	})

	if err := eg.Wait(); err != nil {
		return 1
	}
	return 0
}
