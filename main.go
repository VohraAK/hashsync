package main

import (
	"log/slog"
	"os"

	"github.com/VohraAK/hashsync/internal/logger"
	"github.com/VohraAK/hashsync/internal/merkle"
)

func main() {

	logger.Init()

	fpath := "./"

	file, err := os.Open(fpath)

	if err != nil {
		slog.Error("could not read file",
			slog.String("error", err.Error()),
		)
	}

	defer file.Close()

	root, err := merkle.BuildTree(fpath)
	if err != nil {
		slog.Error("error in building tree",
			slog.String("error", err.Error()),
		)
		return
	}
	
	root.Dump()
}
