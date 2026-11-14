package merkle

// Tests for Tree.Insert.
//
// Main oracle: after any successful Insert the in-memory tree must equal a fresh
// BuildTree of the same directory (see diffNodes / assertMatchesFresh).
//
// Paths: every test uses ONE root string, the one returned by newRoot, for both
// BuildTree and the paths handed to Insert. On macOS t.TempDir() sits under the
// symlink /var -> /private/var and the code does not resolve symlinks, so
// mixing the two spellings of the same directory would not work. Nothing here
// mixes them.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/VohraAK/hashsync/internal/chunker"
)

func TestMain(m *testing.M) {
	// BuildTree/buildNode log through slog. Keep test output clean; nothing asserts on logs.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// ---------------------------------------------------------------------------
// disk helpers
// ---------------------------------------------------------------------------

// newRoot returns a fresh, empty directory whose last element is "dir", so that
// sibling-with-shared-prefix tests can use "<root>2".
func newRoot(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "dir")
	mkdir(t, root)
	return root
}

func mkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	mkdir(t, filepath.Dir(path))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// randBytes returns n deterministic pseudo-random bytes for the given seed.
func randBytes(seed int64, n int) []byte {
	b := make([]byte, n)
	rand.New(rand.NewSource(seed)).Read(b)
	return b
}

func seedOf(s string) int64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return int64(h.Sum64())
}

// put writes root/rel (slash separated) with n deterministic random bytes,
// seeded from rel, and returns the absolute path.
func put(t *testing.T, root, rel string, n int) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	writeFile(t, p, randBytes(seedOf(rel), n))
	return p
}

// putDir creates root/rel as a directory and returns the absolute path.
func putDir(t *testing.T, root, rel string) string {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	mkdir(t, p)
	return p
}

// makeSubtree fills dir with files, nested folders and an empty folder.
func makeSubtree(t *testing.T, dir string) {
	t.Helper()
	put(t, dir, "a.txt", 50)
	put(t, dir, "z.txt", 0)
	put(t, dir, "b/c.txt", 3000)
	put(t, dir, "b/d/e.bin", 70000)
	putDir(t, dir, "b/empty")
}

// makeFixture builds the base directory every table case starts from.
//
//	a.txt c.txt e.txt            files (root children sort: a.txt c.txt e.txt emptydir other sub)
//	emptydir/                    empty folder
//	other/o.txt
//	sub/{m.txt, n.txt(0 B)}
//	sub/deep/x.bin               bigger than the max chunk size -> several chunks
func makeFixture(t *testing.T, root string) {
	t.Helper()
	opts := chunker.FastCDCOpts
	put(t, root, "a.txt", 100)
	put(t, root, "c.txt", 2500)
	put(t, root, "e.txt", 7)
	putDir(t, root, "emptydir")
	put(t, root, "other/o.txt", 321)
	put(t, root, "sub/m.txt", 1000)
	put(t, root, "sub/n.txt", 0)
	put(t, root, "sub/deep/x.bin", opts.MaxSize+opts.MaxSize/2)
}

func mustBuild(t *testing.T, root string) *Tree {
	t.Helper()
	tree, err := BuildTree(root)
	if err != nil {
		t.Fatalf("BuildTree(%q): %v", root, err)
	}
	return tree
}

// creators: functions that make a new node on disk and return its absolute path.
type creator func(t *testing.T, root string) string

func newFile(rel string, n int) creator {
	return func(t *testing.T, root string) string { return put(t, root, rel, n) }
}

func newDir(rel string) creator {
	return func(t *testing.T, root string) string { return putDir(t, root, rel) }
}

func newSubtree(rel string) creator {
	return func(t *testing.T, root string) string {
		p := putDir(t, root, rel)
		makeSubtree(t, p)
		return p
	}
}

// ---------------------------------------------------------------------------
// oracle: tree vs fresh BuildTree
// ---------------------------------------------------------------------------

func childNames(children []*Node) []string {
	out := make([]string, len(children))
	for i, c := range children {
		if c == nil {
			out[i] = "<nil>"
		} else {
			out[i] = c.name
		}
	}
	return out
}

// diffNodes compares two subtrees field by field and returns a description of
// the first difference, or "" when they are identical. Compared: path, name,
// type, chunk list (offset, hash, size), children count and order, size, hash.
//
// Size and hash of a folder are derived from its children, so they are checked
// after the children. That way the report names the deepest node that differs
// instead of the root, whose hash differs whenever anything below it does.
func diffNodes(got, want *Node) string {
	if got == nil || want == nil {
		if got == want {
			return ""
		}
		return fmt.Sprintf("nil mismatch (got nil: %v, want nil: %v)", got == nil, want == nil)
	}
	at := fmt.Sprintf("node %q: ", want.path)

	if got.path != want.path {
		return fmt.Sprintf("path: got %q, want %q", got.path, want.path)
	}
	if got.name != want.name {
		return at + fmt.Sprintf("name: got %q, want %q", got.name, want.name)
	}
	if got.nodeType != want.nodeType {
		return at + fmt.Sprintf("type: got %v, want %v", got.nodeType, want.nodeType)
	}
	if len(got.chunks) != len(want.chunks) {
		return at + fmt.Sprintf("chunk count: got %d, want %d", len(got.chunks), len(want.chunks))
	}
	for i := range want.chunks {
		if got.chunks[i] != want.chunks[i] {
			return at + fmt.Sprintf("chunk %d: got %+v, want %+v", i, got.chunks[i], want.chunks[i])
		}
	}
	if len(got.children) != len(want.children) {
		return at + fmt.Sprintf("children count: got %d %v, want %d %v",
			len(got.children), childNames(got.children), len(want.children), childNames(want.children))
	}
	if !slices.Equal(childNames(got.children), childNames(want.children)) {
		return at + fmt.Sprintf("children order: got %v, want %v", childNames(got.children), childNames(want.children))
	}
	for i := range want.children {
		if d := diffNodes(got.children[i], want.children[i]); d != "" {
			return d
		}
	}
	if got.size != want.size {
		return at + fmt.Sprintf("size: got %d, want %d", got.size, want.size)
	}
	if got.hash != want.hash {
		return at + fmt.Sprintf("hash: got %s, want %s", got.hash, want.hash)
	}
	return ""
}

// assertMatchesFresh is the main assertion: tree must equal BuildTree(root).
func assertMatchesFresh(t *testing.T, tree *Tree, root string) {
	t.Helper()
	fresh := mustBuild(t, root)
	if d := diffNodes(tree.root, fresh.root); d != "" {
		t.Errorf("tree differs from a fresh BuildTree(%q): %s", root, d)
	}
}

// ---------------------------------------------------------------------------
// snapshots: record values and pointers so "unchanged" can be checked exactly
// ---------------------------------------------------------------------------

type nodeRec struct {
	ptr      *Node
	name     string
	nodeType NodeType
	size     int64
	hash     string
	chunks   []chunker.Chunk
	children []*Node
}

func recOf(n *Node) nodeRec {
	return nodeRec{
		ptr:      n,
		name:     n.name,
		nodeType: n.nodeType,
		size:     n.size,
		hash:     n.hash,
		chunks:   slices.Clone(n.chunks),
		children: slices.Clone(n.children),
	}
}

// diff returns the first difference between two records, "" when identical.
func (r nodeRec) diff(o nodeRec) string {
	switch {
	case r.ptr != o.ptr:
		return "node pointer changed"
	case r.name != o.name:
		return fmt.Sprintf("name %q -> %q", r.name, o.name)
	case r.nodeType != o.nodeType:
		return fmt.Sprintf("type %v -> %v", r.nodeType, o.nodeType)
	case r.size != o.size:
		return fmt.Sprintf("size %d -> %d", r.size, o.size)
	case r.hash != o.hash:
		return fmt.Sprintf("hash %s -> %s", r.hash, o.hash)
	case !slices.Equal(r.chunks, o.chunks):
		return "chunks changed"
	case !slices.Equal(r.children, o.children):
		return fmt.Sprintf("children changed: %v -> %v", childNames(r.children), childNames(o.children))
	}
	return ""
}

type treeSnap struct {
	root  *Node
	recs  map[string]nodeRec // keyed by node path
	count int
}

func takeSnapshot(root *Node) treeSnap {
	s := treeSnap{root: root, recs: map[string]nodeRec{}}
	var visit func(n *Node)
	visit = func(n *Node) {
		s.recs[n.path] = recOf(n)
		s.count++
		for _, c := range n.children {
			visit(c)
		}
	}
	if root != nil {
		visit(root)
	}
	return s
}

func countNodes(n *Node) int {
	c := 1
	for _, ch := range n.children {
		c += countNodes(ch)
	}
	return c
}

// assertUnchanged checks that the tree is exactly what the snapshot recorded:
// same root pointer, same node set, and every node identical in value and
// pointer (including its children list).
func assertUnchanged(t *testing.T, tree *Tree, before treeSnap) {
	t.Helper()
	if tree.root != before.root {
		t.Errorf("tree root pointer changed")
	}
	after := takeSnapshot(tree.root)
	if after.count != before.count {
		t.Errorf("node count changed: %d -> %d", before.count, after.count)
	}
	for path, b := range before.recs {
		a, ok := after.recs[path]
		if !ok {
			t.Errorf("node %q disappeared", path)
			continue
		}
		if d := b.diff(a); d != "" {
			t.Errorf("node %q changed: %s", path, d)
		}
	}
	for path := range after.recs {
		if _, ok := before.recs[path]; !ok {
			t.Errorf("unexpected new node %q", path)
		}
	}
}

// ---------------------------------------------------------------------------
// invariants checked directly (independent of walk/search/BuildTree)
// ---------------------------------------------------------------------------

// childByName finds a child with a linear scan (not the binary search under test).
func childByName(n *Node, name string) *Node {
	for _, c := range n.children {
		if c.name == name {
			return c
		}
	}
	return nil
}

// checkTreeInvariants walks the whole tree and checks structural rules that
// must hold at all times.
func checkTreeInvariants(t *testing.T, n *Node) {
	t.Helper()
	if len(n.hash) != sha256.Size*2 {
		t.Errorf("node %q: hash %q is not a sha256 hex string", n.path, n.hash)
	}
	switch n.nodeType {
	case FILE:
		if len(n.children) != 0 {
			t.Errorf("file %q has %d children", n.path, len(n.children))
		}
		var sum int64
		for i, c := range n.chunks {
			if int64(c.Offset) != sum {
				t.Errorf("file %q: chunk %d offset %d, want %d", n.path, i, c.Offset, sum)
			}
			sum += int64(c.Size)
		}
		if sum != n.size {
			t.Errorf("file %q: chunk sizes sum to %d, size is %d", n.path, sum, n.size)
		}
	case FOLDER:
		if len(n.chunks) != 0 {
			t.Errorf("folder %q has %d chunks", n.path, len(n.chunks))
		}
		var sum int64
		for i, c := range n.children {
			if c.path != filepath.Join(n.path, c.name) || c.name != filepath.Base(c.path) {
				t.Errorf("folder %q: child %d has inconsistent path %q / name %q", n.path, i, c.path, c.name)
			}
			if i > 0 && !(n.children[i-1].name < c.name) { // strict: also rules out duplicates
				t.Errorf("folder %q: children not strictly sorted bytewise: %q before %q",
					n.path, n.children[i-1].name, c.name)
			}
			sum += c.size
			checkTreeInvariants(t, c)
		}
		if sum != n.size {
			t.Errorf("folder %q: size %d, children sum to %d", n.path, n.size, sum)
		}
	default:
		t.Errorf("node %q: unknown type %v", n.path, n.nodeType)
	}
}

// checkInsertInvariants verifies, after a successful Insert of newPath (which
// returned got), everything section 2 of the plan asks for. before is the
// snapshot taken before the Insert.
func checkInsertInvariants(t *testing.T, tree *Tree, before treeSnap, newPath string, got *Node) {
	t.Helper()
	if got == nil {
		t.Fatalf("Insert(%q) returned a nil node with a nil error", newPath)
	}
	root := tree.root

	rel, err := filepath.Rel(root.path, newPath)
	if err != nil {
		t.Fatalf("rel(%q, %q): %v", root.path, newPath, err)
	}
	comps := strings.Split(rel, string(filepath.Separator))

	// ancestors root..parent, found by linear scan
	chain := []*Node{root}
	for _, comp := range comps[:len(comps)-1] {
		next := childByName(chain[len(chain)-1], comp)
		if next == nil {
			t.Fatalf("ancestor %q of %q is not in the tree", comp, newPath)
		}
		chain = append(chain, next)
	}
	parent := chain[len(chain)-1]

	// the returned node is the very node stored in the parent's children, exactly once
	occurrences := 0
	for _, c := range parent.children {
		if c == got {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("returned node appears %d times in parent %q children, want exactly 1", occurrences, parent.path)
	}
	if got.path != newPath || got.name != comps[len(comps)-1] {
		t.Errorf("returned node has path %q name %q, want path %q name %q",
			got.path, got.name, newPath, comps[len(comps)-1])
	}

	// whole-tree rules: sorted children, sizes, chunk bookkeeping, paths
	checkTreeInvariants(t, root)

	// every ancestor: hash changed, size grew by exactly the new node's size
	ancestors := map[string]bool{}
	for _, a := range chain {
		ancestors[a.path] = true
		b, ok := before.recs[a.path]
		if !ok {
			t.Errorf("ancestor %q was not in the pre-insert snapshot", a.path)
			continue
		}
		if a.hash == b.hash {
			t.Errorf("ancestor %q: hash did not change", a.path)
		}
		if a.size != b.size+got.size {
			t.Errorf("ancestor %q: size %d, want %d (old %d + new node %d)", a.path, a.size, b.size+got.size, b.size, got.size)
		}
	}
	if root.hash == before.recs[root.path].hash {
		t.Errorf("root hash did not change")
	}

	// ancestors' children lists: the parent gained exactly the new node, the others are unchanged
	for _, a := range chain {
		b, ok := before.recs[a.path]
		if !ok {
			continue
		}
		cur := a.children
		if a == parent {
			cur = slices.DeleteFunc(slices.Clone(a.children), func(c *Node) bool { return c == got })
		}
		if !slices.Equal(cur, b.children) {
			t.Errorf("ancestor %q: children list changed beyond the insert: was %v, now %v",
				a.path, childNames(b.children), childNames(cur))
		}
	}

	// everything else is untouched: same pointer, size, hash, chunks, children
	for path, b := range before.recs {
		if ancestors[path] {
			continue
		}
		if d := b.diff(recOf(b.ptr)); d != "" {
			t.Errorf("unrelated node %q was modified: %s", path, d)
		}
	}

	// nothing was added besides the new node's own subtree
	if want := before.count + countNodes(got); takeSnapshot(root).count != want {
		t.Errorf("node count %d, want %d", takeSnapshot(root).count, want)
	}
}

// ---------------------------------------------------------------------------
// runner for success cases
// ---------------------------------------------------------------------------

// runInsert builds root from fixture (nil = empty root), builds the tree,
// creates the new node on disk, inserts it, then applies the oracle and the
// direct invariants. It returns the tree, the inserted node and its path.
func runInsert(t *testing.T, fixture func(*testing.T, string), create creator) (*Tree, *Node, string) {
	t.Helper()
	root := newRoot(t)
	if fixture != nil {
		fixture(t, root)
	}
	tree := mustBuild(t, root)
	before := takeSnapshot(tree.root)

	newPath := create(t, root)
	got, err := tree.Insert(newPath)
	if err != nil {
		t.Fatalf("Insert(%q): %v", newPath, err)
	}
	checkInsertInvariants(t, tree, before, newPath, got)
	assertMatchesFresh(t, tree, root)
	return tree, got, newPath
}

// ---------------------------------------------------------------------------
// 1. success paths
// ---------------------------------------------------------------------------

func TestInsertSuccess(t *testing.T) {
	opts := chunker.FastCDCOpts

	cases := []struct {
		name   string
		create creator
	}{
		// where
		{"file into root", newFile("d2.txt", 1234)},
		{"file into nested subfolder", newFile("sub/deep/y.txt", 400)},
		{"file into mid-level subfolder", newFile("other/p.txt", 64)},
		{"folder subtree into root", newSubtree("proj")},
		{"folder subtree into nested subfolder", newSubtree("sub/deep/proj")},
		{"empty folder into root", newDir("emptydir2")},
		{"empty folder into nested subfolder", newDir("sub/deep/emptyleaf")},
		{"0-byte file into root", newFile("zero.txt", 0)},
		{"0-byte file into nested subfolder", newFile("sub/deep/zero.txt", 0)},

		// into a folder that is empty before the insert
		{"file into empty folder", newFile("emptydir/f.txt", 10)},
		{"folder into empty folder", newDir("emptydir/inner")},
		{"subtree into empty folder", newSubtree("emptydir/tree")},

		// sizes around the chunker's limits
		{"1-byte file", newFile("one.bin", 1)},
		{"file just under min chunk size", newFile("undermin.bin", opts.MinSize-1)},
		{"file exactly max chunk size", newFile("exactmax.bin", opts.MaxSize)},
		{"file just over max chunk size", newFile("overmax.bin", opts.MaxSize+1)},

		// position in the root folder. Root children sort as: a.txt c.txt e.txt emptydir other sub
		{"root: before all (digit)", newFile("0.txt", 20)},
		{"root: before all (upper case B sorts before a)", newFile("B.txt", 20)},
		{"root: before all (upper case Z sorts before a)", newDir("Zebra")},
		{"root: between siblings", newFile("d.txt", 20)},
		{"root: between siblings, prefix of a sibling name", newFile("emptydir.bak", 20)},
		{"root: between siblings, sibling name is its prefix", newFile("e.txt2", 20)},
		{"root: after sibling with same prefix", newFile("sub.txt", 20)},
		{"root: after all", newFile("zzz.txt", 20)},
		{"root: after all (folder)", newDir("zzzdir")},

		// position in a nested folder. sub children sort as: deep m.txt n.txt
		{"sub: before all (upper case)", newFile("sub/Zeta", 20)},
		{"sub: between siblings", newFile("sub/e.txt", 20)},
		{"sub: after all", newFile("sub/zz", 20)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runInsert(t, makeFixture, tc.create)
		})
	}
}

// Inserting into a root that has no children yet.
func TestInsertIntoEmptyRoot(t *testing.T) {
	t.Run("file", func(t *testing.T) {
		runInsert(t, nil, newFile("f.txt", 100))
	})
	t.Run("folder with files", func(t *testing.T) {
		runInsert(t, nil, newSubtree("proj"))
	})
	t.Run("empty folder", func(t *testing.T) {
		runInsert(t, nil, newDir("e"))
	})
}

// What the chunker does with empty input, which both the 0-byte file and the
// empty folder cases rely on: no error and no chunks.
func TestEmptyInputChunking(t *testing.T) {
	chunks, err := chunker.ChunkFile(bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("ChunkFile(empty): %v", err)
	}
	if len(chunks) != 0 {
		t.Fatalf("ChunkFile(empty) returned %d chunks, want 0: %+v", len(chunks), chunks)
	}
}

// An empty file has no chunks, so its hash input is just the size "0"; an empty
// folder hashes the empty string.
func TestInsertEmptyFileAndFolderHashes(t *testing.T) {
	_, file, _ := runInsert(t, makeFixture, newFile("zero.txt", 0))
	if file.size != 0 || len(file.chunks) != 0 {
		t.Errorf("0-byte file: size %d, %d chunks; want 0 and 0", file.size, len(file.chunks))
	}
	want := sha256.Sum256([]byte("0"))
	if file.hash != hex.EncodeToString(want[:]) {
		t.Errorf("0-byte file hash %s, want sha256(\"0\") %s", file.hash, hex.EncodeToString(want[:]))
	}

	_, dir, _ := runInsert(t, makeFixture, newDir("emptydir2"))
	if dir.size != 0 || len(dir.children) != 0 {
		t.Errorf("empty folder: size %d, %d children; want 0 and 0", dir.size, len(dir.children))
	}
	want = sha256.Sum256(nil)
	if dir.hash != hex.EncodeToString(want[:]) {
		t.Errorf("empty folder hash %s, want sha256(\"\") %s", dir.hash, hex.EncodeToString(want[:]))
	}
}

// A file bigger than the max chunk size must come out as several chunks that
// tile the file exactly. The size comes from chunker.FastCDCOpts, not a constant.
func TestInsertMultiChunkFile(t *testing.T) {
	opts := chunker.FastCDCOpts
	size := 3*opts.MaxSize + opts.MaxSize/2 + 17
	minChunks := (size + opts.MaxSize - 1) / opts.MaxSize // every chunk is <= MaxSize

	for _, rel := range []string{"big.bin", "sub/deep/big.bin"} {
		t.Run(rel, func(t *testing.T) {
			_, node, _ := runInsert(t, makeFixture, newFile(rel, size))

			if node.size != int64(size) {
				t.Errorf("size %d, want %d", node.size, size)
			}
			if len(node.chunks) < minChunks {
				t.Fatalf("%d chunks, want at least %d (size %d, max chunk %d)", len(node.chunks), minChunks, size, opts.MaxSize)
			}
			total := 0
			for i, c := range node.chunks {
				if c.Offset != total {
					t.Errorf("chunk %d: offset %d, want %d", i, c.Offset, total)
				}
				if c.Size > opts.MaxSize {
					t.Errorf("chunk %d: size %d exceeds max %d", i, c.Size, opts.MaxSize)
				}
				if i < len(node.chunks)-1 && c.Size < opts.MinSize {
					t.Errorf("chunk %d: size %d below min %d", i, c.Size, opts.MinSize)
				}
				total += c.Size
			}
			if total != size {
				t.Errorf("chunk sizes sum to %d, want %d", total, size)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. error cases: error returned AND tree unchanged
// ---------------------------------------------------------------------------

func TestInsertErrors(t *testing.T) {
	cases := []struct {
		name string
		// setup prepares the disk (the tree was built before this runs) and returns
		// the path to hand to Insert.
		setup func(t *testing.T, root string) string
	}{
		{"path does not exist", func(t *testing.T, root string) string {
			return filepath.Join(root, "nope.txt")
		}},
		{"path does not exist, in existing subfolder", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "nope.txt")
		}},
		{"empty path", func(t *testing.T, root string) string {
			return ""
		}},
		{"in tree but deleted from disk", func(t *testing.T, root string) string {
			p := filepath.Join(root, "a.txt")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			return p
		}},

		{"already in tree: file", func(t *testing.T, root string) string {
			return filepath.Join(root, "a.txt")
		}},
		{"already in tree: nested file", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "m.txt")
		}},
		{"already in tree: folder with children", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub")
		}},
		{"already in tree: empty folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "emptydir")
		}},
		{"already in tree: content changed on disk (Insert is not an update)", func(t *testing.T, root string) string {
			return put(t, root, "a.txt", 999)
		}},
		{"the root path itself", func(t *testing.T, root string) string {
			return root
		}},
		{"the root path itself, trailing slash", func(t *testing.T, root string) string {
			return root + string(filepath.Separator)
		}},
		{"the root path itself, trailing /.", func(t *testing.T, root string) string {
			return root + string(filepath.Separator) + "."
		}},

		{"relative path", func(t *testing.T, root string) string {
			put(t, root, "rel.txt", 10)
			t.Chdir(root)
			return "rel.txt"
		}},
		{"relative path with ./", func(t *testing.T, root string) string {
			put(t, root, "rel.txt", 10)
			t.Chdir(root)
			return "." + string(filepath.Separator) + "rel.txt"
		}},
		{"relative path into subfolder", func(t *testing.T, root string) string {
			put(t, root, "sub/rel.txt", 10)
			t.Chdir(root)
			return filepath.Join("sub", "rel.txt")
		}},
		{"relative path, already in tree", func(t *testing.T, root string) string {
			t.Chdir(root)
			return "a.txt"
		}},

		{"outside root: sibling folder sharing the root's string prefix (file)", func(t *testing.T, root string) string {
			// root = <tmp>/dir, path = <tmp>/dir2/file
			return put(t, root+"2", "file", 10)
		}},
		{"outside root: sibling folder sharing the root's string prefix (folder)", func(t *testing.T, root string) string {
			return putDir(t, filepath.Dir(root), "dir2")
		}},
		{"outside root: file next to the root", func(t *testing.T, root string) string {
			return put(t, filepath.Dir(root), "outside.txt", 10)
		}},
		{"outside root: the parent of the root", func(t *testing.T, root string) string {
			return filepath.Dir(root)
		}},
		{"outside root: escapes via ..", func(t *testing.T, root string) string {
			put(t, filepath.Dir(root), "escaped.txt", 10)
			return root + "/sub/../../escaped.txt"
		}},

		{"missing intermediate folder (on disk, not in tree)", func(t *testing.T, root string) string {
			return put(t, root, "newdir/f.txt", 10)
		}},
		{"missing intermediate folder under a nested folder", func(t *testing.T, root string) string {
			return put(t, root, "sub/newdir/f.txt", 10)
		}},
		{"two missing intermediate folders", func(t *testing.T, root string) string {
			return put(t, root, "n1/n2/f.txt", 10)
		}},

		{"parent is a file in the tree (folder on disk)", func(t *testing.T, root string) string {
			// the tree says a.txt is a file; on disk it is now a folder holding x.txt
			if err := os.Remove(filepath.Join(root, "a.txt")); err != nil {
				t.Fatal(err)
			}
			return put(t, root, "a.txt/x.txt", 10)
		}},
		{"ancestor is a file in the tree (folder on disk), deeper path", func(t *testing.T, root string) string {
			if err := os.Remove(filepath.Join(root, "sub", "m.txt")); err != nil {
				t.Fatal(err)
			}
			return put(t, root, "sub/m.txt/inner/y.txt", 10)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)
			before := takeSnapshot(tree.root)

			path := tc.setup(t, root)
			got, err := tree.Insert(path)

			if err == nil {
				t.Errorf("Insert(%q) succeeded, want an error", path)
			}
			if got != nil {
				t.Errorf("Insert(%q) returned a node together with an error", path)
			}
			assertUnchanged(t, tree, before)
		})
	}
}

// A tree with no root must refuse to insert, not panic.
func TestInsertNilRoot(t *testing.T) {
	root := newRoot(t)
	p := put(t, root, "f.txt", 10)

	tree := &Tree{}
	got, err := tree.Insert(p)
	if err == nil {
		t.Errorf("Insert on a tree with a nil root succeeded, want an error")
	}
	if got != nil {
		t.Errorf("Insert returned a node together with an error")
	}
	if tree.root != nil {
		t.Errorf("tree root is no longer nil")
	}
}

// Inserting the same node twice: the first works, the second fails and changes nothing.
func TestInsertTwice(t *testing.T) {
	root := newRoot(t)
	makeFixture(t, root)
	tree := mustBuild(t, root)

	p := put(t, root, "sub/twice.txt", 100)
	if _, err := tree.Insert(p); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	before := takeSnapshot(tree.root)

	got, err := tree.Insert(p)
	if err == nil || got != nil {
		t.Errorf("second Insert(%q) = (%v, %v), want (nil, error)", p, got, err)
	}
	assertUnchanged(t, tree, before)
	assertMatchesFresh(t, tree, root)
}

// ---------------------------------------------------------------------------
// 4. sequences
// ---------------------------------------------------------------------------

// Many Inserts in a row, each checked against a fresh BuildTree and the
// invariants. Names, sizes and target folders come from a fixed seed, so the
// run is reproducible. Names carry a unique counter so they never collide, even
// on a case-insensitive file system, and prefixes mix upper case, lower case,
// digits and "_" to exercise bytewise ordering.
func TestInsertRandomSequence(t *testing.T) {
	root := newRoot(t)
	makeFixture(t, root)
	tree := mustBuild(t, root)

	rng := rand.New(rand.NewSource(42))
	folders := []string{
		root,
		filepath.Join(root, "sub"),
		filepath.Join(root, "sub", "deep"),
		filepath.Join(root, "other"),
		filepath.Join(root, "emptydir"),
	}
	prefixes := []string{"a", "B", "Z", "m", "_", "0", "zz", "e"}
	sizes := []int{0, 1, 17, 300, 4096, 20000}

	for i := 0; i < 40; i++ {
		parent := folders[rng.Intn(len(folders))]
		name := fmt.Sprintf("%s%02d", prefixes[rng.Intn(len(prefixes))], i)
		path := filepath.Join(parent, name)

		if rng.Intn(4) == 0 {
			mkdir(t, path)
			for j := rng.Intn(3); j > 0; j-- {
				writeFile(t, filepath.Join(path, fmt.Sprintf("f%d", j)), randBytes(int64(i*10+j), sizes[rng.Intn(len(sizes))]))
			}
			folders = append(folders, path)
		} else {
			writeFile(t, path, randBytes(int64(i), sizes[rng.Intn(len(sizes))]))
		}

		before := takeSnapshot(tree.root)
		got, err := tree.Insert(path)
		if err != nil {
			t.Fatalf("step %d: Insert(%q): %v", i, path, err)
		}
		checkInsertInvariants(t, tree, before, path, got)
		assertMatchesFresh(t, tree, root)
		if t.Failed() {
			t.Fatalf("stopping at step %d (%s)", i, path)
		}
	}
}

// Insert a folder, then insert new files inside it. The folder node returned by
// the first Insert must stay in the tree and pick up the new content.
func TestInsertFolderThenFileInside(t *testing.T) {
	root := newRoot(t)
	makeFixture(t, root)
	tree := mustBuild(t, root)

	proj := newSubtree("proj")(t, root)
	before := takeSnapshot(tree.root)
	projNode, err := tree.Insert(proj)
	if err != nil {
		t.Fatalf("Insert folder: %v", err)
	}
	checkInsertInvariants(t, tree, before, proj, projNode)
	assertMatchesFresh(t, tree, root)

	for _, rel := range []string{"proj/b/d/new.txt", "proj/0first.txt", "proj/zlast.txt", "proj/b/empty/in-empty.txt"} {
		sizeBefore, hashBefore := projNode.size, projNode.hash

		p := put(t, root, rel, 250)
		before := takeSnapshot(tree.root)
		got, err := tree.Insert(p)
		if err != nil {
			t.Fatalf("Insert(%q): %v", p, err)
		}
		checkInsertInvariants(t, tree, before, p, got)
		assertMatchesFresh(t, tree, root)

		if childByName(tree.root, "proj") != projNode {
			t.Errorf("after inserting %s: folder node from the first Insert is no longer in the tree", rel)
		}
		if projNode.size != sizeBefore+250 {
			t.Errorf("after inserting %s: folder size %d, want %d", rel, projNode.size, sizeBefore+250)
		}
		if projNode.hash == hashBefore {
			t.Errorf("after inserting %s: folder hash did not change", rel)
		}
	}
}

func permutations(n int) [][]int {
	var out [][]int
	var rec func(cur []int, used []bool)
	rec = func(cur []int, used []bool) {
		if len(cur) == n {
			out = append(out, slices.Clone(cur))
			return
		}
		for i := 0; i < n; i++ {
			if !used[i] {
				used[i] = true
				rec(append(cur, i), used)
				used[i] = false
			}
		}
	}
	rec(nil, make([]bool, n))
	return out
}

// The same set of new nodes inserted in every possible order must give the
// same final root hash (and the tree must match a fresh BuildTree each time).
// Each order gets its own root; root hashes do not depend on the root's own
// path, and all contents are deterministic.
func TestInsertOrderIndependence(t *testing.T) {
	newNodes := []creator{
		newFile("b.txt", 700),
		newFile("sub/q.txt", 90),
		newDir("emptydir2"),
		newSubtree("tree1"),
		newFile("emptydir/in.txt", 12),
	}

	var wantHash string
	for _, perm := range permutations(len(newNodes)) {
		t.Run(fmt.Sprint(perm), func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)

			// all new nodes exist on disk before the first Insert
			paths := make([]string, len(newNodes))
			for i, create := range newNodes {
				paths[i] = create(t, root)
			}
			for _, i := range perm {
				before := takeSnapshot(tree.root)
				got, err := tree.Insert(paths[i])
				if err != nil {
					t.Fatalf("Insert(%q): %v", paths[i], err)
				}
				checkInsertInvariants(t, tree, before, paths[i], got)
			}
			assertMatchesFresh(t, tree, root)

			if wantHash == "" {
				wantHash = tree.root.hash
			} else if tree.root.hash != wantHash {
				t.Errorf("final root hash %s, want %s (same as the first order)", tree.root.hash, wantHash)
			}
		})
	}
}
