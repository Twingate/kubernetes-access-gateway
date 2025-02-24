package log

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Used to allow testing.
var (
	zapReplaceGlobals = zap.ReplaceGlobals
	zapRedirectStdLog = zap.RedirectStdLog
)

var destroyFunc func()

func InitializeLogger(name string, debug bool) {
	loggingConfig := loggingConfiguration(debug)

	const linesToSkip = 2

	logger, err := loggingConfig.Build(zap.AddCallerSkip(linesToSkip))
	if err != nil {
		panic(fmt.Sprintf("failed to initialize logger: %v", err))
	}

	if name != "" {
		logger = logger.Named(name)
	}

	logger = logger.With(zap.String("version", "0.0.1")) // TODO: version

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
