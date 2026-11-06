package main

import (
	"os"
	"log"
	"fmt"
	
	"github.com/VohraAK/hashsync/internal/chunker"
)

func main() {
	filename := "test-dir/large.bin"
	
	file, err := os.Open(filename)

	if err != nil {
		log.Fatal("ERROR IN READING FILE!")
	}
	
	defer file.Close()

	chunks, err := chunker.ChunkFile(file)
	
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	for i, c := range chunks {
		fmt.Printf("%d: %+v\n", i, c) // %+v prints field names and values
	}

}