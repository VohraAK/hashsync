package main

import (
	// "fmt"
	"log"
	"os"

	// "github.com/VohraAK/hashsync/internal/chunker"
	"github.com/VohraAK/hashsync/internal/merkle"
)

func main() {
	filename := "test-dir"

	file, err := os.Open(filename)

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

	
	root := &merkle.Node{}
	root.CreateTree(filename)

}
