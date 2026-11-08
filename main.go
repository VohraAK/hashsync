package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/VohraAK/hashsync/internal/logger"
	"github.com/VohraAK/hashsync/internal/merkle"
)

func main() {

	logger.Init()

	fpath := "/Users/abdullah/Desktop"

	file, err := os.Open(fpath)

	if err != nil {
		slog.Error("could not read file",
			slog.String("error", err.Error()),
		)
	}

	defer file.Close()

	// chunks, err := chunker.ChunkFile(file)

	// if err != nil {
	// 	log.Fatal(err)
	// 	os.Exit(1)
	// }

	// for i, c := range chunks {
	// 	fmt.Printf("%d: %+v\n", i, c) // %+v prints field names and values
	// }

	root, err := merkle.BuildTree(fpath)
	if err != nil {
		slog.Error("error in building tree",
			slog.String("error", err.Error()),
		)
	}
	root.Dump()
}
