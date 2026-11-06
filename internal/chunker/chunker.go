package chunker

import (
	"crypto/sha256"
	"io"
	// "os"

	// "bytes"
	"log"
	// "fmt"
	"encoding/hex"

	"github.com/VohraAK/hashsync/internal/types"

	"github.com/jotfs/fastcdc-go"
)

func ChunkFile(file io.Reader) ([]types.Chunk, error) {

	// test function for warmups
	// fastcdc.Chunk contains:
	// type Chunk struct {
		// Offset is the number of bytes from the start of the reader to the beginning of
		// the chunk.
	// 	Offset int
	// 
	// 	// Length is the length of the chunk in bytes. Same as len(Data).
	// 	Length int
	// 
	// 	// Data is the chunk data.
	// 	Data []byte
	// 
	// 	// Fingerprint is the value of the rolling hash algorithm for the chunk data.
	// 	Fingerprint uint64
	// }
	
	chunker, err := fastcdc.NewChunker(file, types.FastCDCOpts)

	if err != nil {
		log.Fatal("ERROR IN CREATING CHUNKER!")
		return nil, err
	}

	chunks := []types.Chunk{}
	
	for {
		chunk, err := chunker.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal("COULD NOT READ CHUNK!")
			return nil, err
		}

		sum := sha256.Sum256(chunk.Data)
		
		chunks = append(chunks, types.Chunk{
			Offset: chunk.Offset,
			Hash: hex.EncodeToString(sum[:]),
			Size: chunk.Length,
		})
	}

	return chunks, nil

}