// Copyright (c) Twingate Inc.
// SPDX-License-Identifier: MPL-2.0

package log

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"k8sgateway/internal/version"
)

// Used to allow testing.
var (
	zapReplaceGlobals = zap.ReplaceGlobals
	zapRedirectStdLog = zap.RedirectStdLog
)

var destroyFunc func()

func InitializeLogger(name string, debug bool) {
	loggingConfig := loggingConfiguration(debug)

	logger, err := loggingConfig.Build()
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}

	if name != "" {
		logger = logger.Named(name)
	}

	logger = logger.With(zap.String("version", version.Version))

	undoGlobals := zapReplaceGlobals(logger)
	undoStd := zapRedirectStdLog(logger)

	destroyFunc = func() {
		defer func() {
			err = logger.Sync()
		}()

		undoGlobals()
		undoStd()
	}

	logger.Sugar().Info("initializing Logger")
}

func Destroy() {
	if destroyFunc != nil {
		destroyFunc()
	}
}

func loggingConfiguration(debug bool) zap.Config {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "levelname",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "message",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	logLevel := zap.InfoLevel
	if debug {
		logLevel = zap.DebugLevel
	}

	zapConfig := zap.Config{
		Level:            zap.NewAtomicLevelAt(logLevel),
		Development:      false,
		Encoding:         "json",
		EncoderConfig:    encoderConfig,
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}

	return zapConfig
}
