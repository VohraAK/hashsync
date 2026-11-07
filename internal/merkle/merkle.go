/*
 * Definition of the Merkle Tree structure
 */

package merkle

import (
	"fmt"
	"log"
	"os"
	// "path/filepath"
	"strconv"
	"strings"

	"github.com/VohraAK/hashsync/internal/chunker"
)

type NodeType int

const (
	FILE NodeType = iota
	FOLDER
)

// Node struct for merkle tree
type Node struct {
	path 		string
	name 		string
	nodeType 	NodeType
	size 		int64
	hash		string
	chunks		[]chunker.Chunk 	// only for FILE nodes; stores ordered list of chunks
	children 	[]*Node				// only for FOLDER nodes; stores all children nodes as rer in SORTED ORDER
}

/*
getHashable returns a hash input string for node contents branched on node type
 */
func (n *Node) getHashable() string {
	if n == nil {
		return ""
	}

	var sb strings.Builder;

	switch n.nodeType {
		case FILE:
			// (hash1 +...+ hashn + size)
			for _, c := range n.chunks {
				sb.WriteString(c.Hash)
			}
			sb.WriteString(strconv.Itoa(int(n.size)))

		case FOLDER:
			// sorted (childname + childtype + childhash) for each child
			for _, child := range n.children {
				sb.WriteString(child.name)
				sb.WriteString("\x00")	// null seperator after name to reduce (very low) hash duplication risk 
				sb.WriteString(strconv.Itoa(int(child.nodeType)))
				sb.WriteString(child.hash)
			}
	}

	return sb.String()
}

/* 
initialise a new Merkle Tree over the directory
*/
// FIX: to build a tree, start from the root node
// 1. build a node for the current entry
// 2. if current entry is a file, chunk&hash and store as file node
// 3. if current entry is a folder, recursivelt build node
func (n *Node) CreateTree(dirPath string) {
	// assuming the caller has validated the path exists
	dir, err := os.ReadDir(dirPath)

	if err != nil {
		log.Fatal(err)
	}

	// iterating over the entries
	// top-level -> bottom-level
	for _, e := range dir {
		info, err := e.Info()

		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("%s | %t\n", info.Name(), info.IsDir())
	}
}

