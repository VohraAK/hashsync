package logger

import (
	"log/slog"
	"os"
)

var programLevel = new(slog.LevelVar)

var slogOpts = slog.HandlerOptions{
	Level: programLevel,
}

func Init() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slogOpts))

	// change slog level here!
	programLevel.Set(slog.LevelInfo)

	slog.SetDefault(logger)
}