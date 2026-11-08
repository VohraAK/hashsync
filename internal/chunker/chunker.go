package chunker

import (
	"crypto/sha256"
	"io"

	// "os"
	// "bytes"
	// "fmt"
	"encoding/hex"

	"github.com/jotfs/fastcdc-go"
)

// a chunk is a sequence of bytes with a size and associated hash
type Chunk struct {		
	Offset 	int
	Hash 	string
	Size 	int
}

// config for fastcdc-go chunking algorithm
var FastCDCOpts = fastcdc.Options{
    MinSize:     16 << 10,  // 16 KiB
    AverageSize: 64 << 10,  // 64 KiB
    MaxSize:     256 << 10, // 256 KiB
}

func ChunkFile(file io.Reader) ([]Chunk, error) {
	chunker, err := fastcdc.NewChunker(file, FastCDCOpts)

	if err != nil {
		return nil, err
	}

	chunks := []Chunk{}
	
	for {
		chunk, err := chunker.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		sum := sha256.Sum256(chunk.Data)
		
		chunks = append(chunks, Chunk{
			Offset: chunk.Offset,
			Hash: hex.EncodeToString(sum[:]),
			Size: chunk.Length,
		})
	}

	return chunks, nil

}