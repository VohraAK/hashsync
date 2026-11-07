package main

import (
	// "fmt"
	"fmt"
	"log"
	"os"

	// "github.com/VohraAK/hashsync/internal/chunker"
	"github.com/VohraAK/hashsync/internal/merkle"
)

func main() {
	fpath := "test-dir"

	file, err := os.Open(fpath)

	if err != nil {
		log.Fatal("ERROR IN READING FILE!")
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
		fmt.Println("ERROR: %w", err)
	}
	root.Dump()

}
