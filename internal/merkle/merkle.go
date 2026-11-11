/*
 * Definition of the Merkle Tree structure
 */

package merkle

import (
	"os"
	"time"
	"log/slog"
	"fmt"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	// "unsafe"

	"github.com/VohraAK/hashsync/internal/chunker"
)

type NodeType int

const (
	FILE NodeType = iota
	FOLDER
)

// converts the enum type to literal strings
func (t NodeType) String() string {
	switch t {
	case FILE:
		return "FILE"
	case FOLDER:
		return "FOLDER"
	default:
		return fmt.Sprintf("NodeType(%d)", int(t))
	}
}

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

// Tree wrapper for the root node
type Tree struct {
	root		*Node
	// could add a path-to-node mapping in the future for faster lookups
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


func chunkPath(fPath string) ([]chunker.Chunk, error) {
	f, e := os.Open(fPath)

	if e != nil {
		return nil, fmt.Errorf("could not open file %s | error: %w", fPath, e)
	}

	defer f.Close()

	chunks, e := chunker.ChunkFile(f)

	if e != nil {
		return nil, fmt.Errorf("could not chunk file %s | error: %w", fPath, e)
	}
	
	return chunks, nil
}


/* 
	initialise a new Merkle Tree over the directory
*/
func BuildTree(rootPath string) (*Tree, error) {
	
	// dirPath is the path to the root dir being watched
	// check if path is correct
	rootInfo, err := os.Stat(rootPath)

	if err != nil {
		return nil, err
	}

	// TODO: make the dirPath absolute while building the tree
	// all nodes will have abs paths
	rootAbsPath, err := filepath.Abs(rootPath)

	if err != nil {
		return nil, err
	}

	slog.Info("building merkle tree",
		slog.String("path", rootAbsPath),
	)

	timeStart := time.Now()
	rootNode, err := buildNode(rootAbsPath, rootInfo)

	if err != nil {
		return nil, err
	}

	duration := time.Since(timeStart)

	slog.Info("tree built", 
		slog.String("duration", duration.String()),
	)

	return &Tree{root: rootNode}, err

}

func buildNode(nodePath string, nodeInfo os.FileInfo) (*Node, error) {

	// to build a tree, start from the root node
	// 1. build a node for the current entry
	// 2. if current entry is a file, chunk&hash and store as file node
	// 3. if current entry is a folder, recursively build nodes for all children in the folder
	n := &Node{
		path: nodePath,
		name: filepath.Base(nodePath),
	}

	if nodeInfo.IsDir() {
		n.nodeType = FOLDER
		
		// make nodes of all the children
		// read the dir with os.ReadDir to get a list of entires
		entries, e := os.ReadDir(nodePath)

		if e != nil {
			return nil, fmt.Errorf("could not read dir entries for %s\n | error: %w", nodePath, e)
		}

		for _, entry := range entries {
			info, e := entry.Info()	// get the file info

			if e != nil {
				return nil, fmt.Errorf("error for info %s | %w", entry.Name(), e)
			}
			
			// make the child node and add to children list
			child, e := buildNode(filepath.Join(nodePath, entry.Name()), info)

			if e != nil {
                return nil, e
            }

			n.children = append(n.children, child)
			n.size += child.size

		}
	} else {
		n.nodeType = FILE
		n.size = nodeInfo.Size()

		// get chunks
		chunks, e := chunkPath(nodePath)

		if e != nil {
			return nil, fmt.Errorf("could not chunk path! %w", e)
		}

		n.chunks = chunks

	}

	// get/set the node hash before returning
	nHashSum := sha256.Sum256([]byte(n.getHashable()))
	n.hash = hex.EncodeToString(nHashSum[:])

	slog.Debug("node created",
		slog.String("path", nodePath),
		slog.Int64("size", n.size),
		slog.String("hash", n.hash),
	)

	return n, nil
}


// tree primitive operations
// 1. insert a new node in the tree
// 2. update a node in the tree
// 3. delete a node from the tree

// walk follows path down the tree (memory only, never touches the disk).
// found == true:  chain ends at the target node, index is its position in its parent's children.
// found == false: chain ends at the parent, index is the sorted insertion position for the target.
// a missing final component is a normal result, not an error.
func (t *Tree) walk(path string) (chain []*Node, index int, found bool, err error) {
	if t.root == nil {
		return nil, 0, false, fmt.Errorf("walk %q: tree root is nil", path)
	}

	// make path relative to the root and reject anything outside of it
	sep := string(filepath.Separator)
	rel, err := filepath.Rel(t.root.path, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+sep) {
		return nil, 0, false, fmt.Errorf("walk %q: path must be absolute and under the tree root %q", path, t.root.path)
	}

	// path is the root itself: return chain with root only
	if rel == "." {
		return []*Node{t.root}, 0, true, nil
	}

	chain = []*Node{t.root}
	current := t.root
	comps := strings.Split(rel, sep)

	for i, comp := range comps {
		// can only descend into folders
		if current.nodeType == FILE {
			return nil, 0, false, fmt.Errorf("walk %q: %q is not a folder", path, current.path)
		}

		idx, ok := current.search(comp)
		last := i == len(comps) - 1

		switch {
		case ok && last:
			// target found
			chain = append(chain, current.children[idx])
			return chain, idx, true, nil
		case ok:
			// found an intermediate folder, keep descending
			current = current.children[idx]
			chain = append(chain, current)
		case last:
			// target missing, but its parent exists: not an error
			return chain, idx, false, nil
		default:
			return nil, 0, false, fmt.Errorf("walk %q: parent folder %q not in tree", path, comp)
		}
	}

	// unreachable: the loop always returns on the last component
	return nil, 0, false, fmt.Errorf("walk %q: no path components", path)
}

// search binary-searches n.children (sorted bytewise by name) for name.
// if found, returns its index and true.
// if not, returns the sorted insertion index and false.
func (n *Node) search(name string) (int, bool) {
	// smallest i where children[i].name >= name (Go string compare is bytewise)
	i := sort.Search(len(n.children), func(i int) bool {
		return n.children[i].name >= name
	})

	found := i < len(n.children) && n.children[i].name == name
	return i, found
}

// insert the new node at the provided path.
// inserts the new node inside an existing folder node
func (t *Tree) Insert(nodePath string) (*Node, error) {

	// check if the path exists
	// check if node exists in tree -> walk and get list of ancestors
	// call buildNode
	// add node in children of its parent(as sorted)
	// resize and rehash up the chain of ancestors

	return nil, nil
}

// modify the node at the provided path.
// the node MUST exist to be updated
func (t *Tree) Update(nodePath string) (*Node, error) {

	return nil, nil
}

// delete the node at the provided path.
func (t *Tree) Delete(nodePath string) (bool, error) {

	return false, nil
}




// dbg funcs
// Dump prints the tree rooted at n in a `tree`-style layout
func (t *Tree) Dump() {
    t.root.dump("", true, true)
}

func (n *Node) dump(prefix string, isLast, isRoot bool) {
    if n == nil {
        return
    }

    connector := ""
    childPrefix := prefix
    if !isRoot {
        if isLast {
            connector, childPrefix = "└── ", prefix+"    "
        } else {
            connector, childPrefix = "├── ", prefix+"│   "
        }
    }

    switch n.nodeType {
    case FOLDER:
        fmt.Printf("%s%s%s/  (%d B, %d children)  %.8s [%s]\n",
            prefix, connector, n.name, n.size, len(n.children), n.hash, n.path)
    case FILE:
        fmt.Printf("%s%s%s  (%d B, %d chunks)  %.8s [%s]\n",
            prefix, connector, n.name, n.size, len(n.chunks), n.hash, n.path)
    }

    for i, c := range n.children {
        c.dump(childPrefix, i == len(n.children)-1, false)
    }
}
