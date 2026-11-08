package main

import (
	"log/slog"
	"os"

	"github.com/VohraAK/hashsync/internal/logger"
	"github.com/VohraAK/hashsync/internal/merkle"
)

func main() {

	logger.Init()

	fpath := "/users/abdullah/Desktop/"

	file, err := os.Open(fpath)

	if err != nil {
		slog.Error("could not read file",
			slog.String("error", err.Error()),
		)
	}

	defer file.Close()

	_, err = merkle.BuildTree(fpath)
	if err != nil {
		slog.Error("error in building tree",
			slog.String("error", err.Error()),
		)
	}
	// root.Dump()
}
