package logger

import (
	"context"
	"fmt"
	"github.com/day0ops/istio-authz/authz-server/pkg/config"
	"github.com/day0ops/istio-authz/authz-server/pkg/version"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sync"
)

type ctxKey struct{}

var once sync.Once

var logger *zap.Logger

// Get initializes a zap.Logger instance if it has not been initialized
// already and returns the same instance for subsequent calls.
func Get() *zap.Logger {
	once.Do(func() {
		encoder := zap.NewProductionEncoderConfig()
		level := zap.NewAtomicLevelAt(getLevelLogger(config.LogLevel))

		zapConfig := zap.NewProductionConfig()
		zapConfig.EncoderConfig = encoder
		zapConfig.Level = level
		zapConfig.OutputPaths = []string{"stdout"}
		zapConfig.ErrorOutputPaths = []string{"stderr"}
		var err error
		logger, err = zapConfig.Build()
		if err != nil {
			fmt.Println("error setting up the logger:", err)
			panic(err)
		}
		logger = logger.With(zap.String("release", version.HumanVersion))
		defer func() {
			// If we cannot sync, there's probably something wrong with outputting logs,
			// so we probably cannot write using fmt.Println either.
			// Hence, ignoring the error for now.
			_ = logger.Sync()
		}()
	})
	return logger
}

func getLevelLogger(level string) zapcore.Level {
	if level == "debug" {
		return zap.DebugLevel
	}
	return zap.InfoLevel
}

// FromCtx returns the Logger associated with the ctx. If no logger
// is associated, the default logger is returned, unless it is nil
// in which case a disabled logger is returned.
func FromCtx(ctx context.Context) *zap.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*zap.Logger); ok {
		return l
	} else if l := logger; l != nil {
		return l
	}

	return zap.NewNop()
}

// WithCtx returns a copy of ctx with the Logger attached.
func WithCtx(ctx context.Context, l *zap.Logger) context.Context {
	if lp, ok := ctx.Value(ctxKey{}).(*zap.Logger); ok {
		if lp == l {
			// Do not store same logger.
			return ctx
		}
	}

	return context.WithValue(ctx, ctxKey{}, l)
}
