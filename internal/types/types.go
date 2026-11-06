package types

// shared package which defines the shape of structures

import (
	"github.com/jotfs/fastcdc-go"
)

// a chunk is a sequence of bytes with a size and associated hash
type Chunk struct {		
	Offset int	`json:"sequence"`
	Hash string		`json:"hash"`
	Size int		`json:"size"`
}

// a file will have a filename, filesize, and a collection of chunks
type FileInfo struct {
	Path string		`json:"filepath"`
	SizeB int64 	`json:"sizeb"`
	Chunks []Chunk 	`json:"chunks"`
}

// funcking for fastcdc-go chunking algorithm
var FastCDCOpts = fastcdc.Options{
    MinSize:     16 << 10,  // 16 KiB
    AverageSize: 64 << 10,  // 64 KiB
    MaxSize:     256 << 10, // 256 KiB
}

// a manifest is a collection of FileInfos 
// type Manifest struct {
// 	Files []FileInfo `json:"files"`
// }
