package merkle

// Tests for Tree.Update.
//
// Same approach as the Insert tests (insert_test.go, whose helpers are reused here):
//   - main oracle: after a successful Update the in-memory tree equals a fresh
//     BuildTree of the same directory (assertMatchesFresh);
//   - direct invariants (checkUpdateInvariants) that do not depend on walk/search/BuildTree;
//   - on any error: nil node AND the tree is exactly what it was (assertUnchanged).
//
// Paths: one root string (newRoot) is used for BuildTree and for every path handed
// to Update. Never mix spellings (macOS /var -> /private/var).

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/VohraAK/hashsync/internal/chunker"
)

// ---------------------------------------------------------------------------
// fixtures and file mutators
// ---------------------------------------------------------------------------

// makeUpdateFixture is makeFixture plus
//
//	big.bin          6 * MaxSize bytes (many chunks, used for the chunk-stability tests)
//	many/f1 .. f5    five small sibling files (first, middle, last position)
func makeUpdateFixture(t *testing.T, root string) {
	t.Helper()
	makeFixture(t, root)
	put(t, root, "big.bin", 6*chunker.FastCDCOpts.MaxSize)
	for i, n := range []int{10, 20, 30, 40, 50} {
		put(t, root, fmt.Sprintf("many/f%d", i+1), n)
	}
}

// mutator changes the file at path on disk.
type mutator func(t *testing.T, path string)

// writeSeeded replaces the file with n pseudo-random bytes from the given seed.
func writeSeeded(seed int64, n int) mutator {
	return func(t *testing.T, path string) { writeFile(t, path, randBytes(seed, n)) }
}

// prefixKept is what put(t, root, rel, n) does: same bytes as the fixture file
// when n is not larger, the old bytes as a prefix when it is.
func prefixKept(rel string, n int) mutator { return writeSeeded(seedOf(rel), n) }

// rewriteSame writes the file's current bytes back (mtime changes, content does not).
func rewriteSame() mutator {
	return func(t *testing.T, path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, data)
	}
}

// restoreBytes writes exact bytes back.
func restoreBytes(data []byte) mutator {
	return func(t *testing.T, path string) { writeFile(t, path, slices.Clone(data)) }
}

// flipByteAt changes one byte, leaving the length alone.
func flipByteAt(pos int) mutator {
	return func(t *testing.T, path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		data[pos] ^= 0xFF
		writeFile(t, path, data)
	}
}

// appendRandom appends n pseudo-random bytes.
func appendRandom(seed int64, n int) mutator {
	return func(t *testing.T, path string) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, path, append(data, randBytes(seed, n)...))
	}
}

func relPath(root, rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }

// ---------------------------------------------------------------------------
// invariants after a successful Update
// ---------------------------------------------------------------------------

// checkUpdateInvariants verifies, after a successful Update(path) that returned
// got, everything the spec asks for. before is the snapshot taken before the
// Update; changed says whether the file's bytes really differ from the bytes the
// tree was built from. Nodes are found by linear scan, not by walk.
func checkUpdateInvariants(t *testing.T, tree *Tree, before treeSnap, path string, got *Node, changed bool) {
	t.Helper()
	if got == nil {
		t.Fatalf("Update(%q) returned a nil node with a nil error", path)
	}
	root := tree.root

	rel, err := filepath.Rel(root.path, path)
	if err != nil {
		t.Fatalf("rel(%q, %q): %v", root.path, path, err)
	}
	comps := strings.Split(rel, string(filepath.Separator))

	// chain root..target, found by linear scan on the tree as it is NOW
	chain := []*Node{root}
	for _, comp := range comps {
		next := childByName(chain[len(chain)-1], comp)
		if next == nil {
			t.Fatalf("%q (component %q) is not in the tree after Update", path, comp)
		}
		chain = append(chain, next)
	}
	target := chain[len(chain)-1]
	parent := chain[len(chain)-2]

	beforeRec, ok := before.recs[path]
	if !ok {
		t.Fatalf("%q was not in the pre-update snapshot", path)
	}

	// identity: the SAME pointer that was in the tree before, in the same slot, once
	if got != beforeRec.ptr {
		t.Errorf("returned node is not the node that was in the tree before the Update")
	}
	if target != beforeRec.ptr {
		t.Errorf("node now stored at %q is not the node that was there before", path)
	}
	occurrences := 0
	for _, c := range parent.children {
		if c == got {
			occurrences++
		}
	}
	if occurrences != 1 {
		t.Errorf("returned node appears %d times in parent %q children, want exactly 1", occurrences, parent.path)
	}
	parentBefore := before.recs[parent.path]
	if i, j := slices.Index(parentBefore.children, beforeRec.ptr), slices.Index(parent.children, got); i != j {
		t.Errorf("node moved inside parent %q: index %d -> %d", parent.path, i, j)
	}
	if got.path != path || got.name != comps[len(comps)-1] {
		t.Errorf("returned node has path %q name %q, want path %q name %q", got.path, got.name, path, comps[len(comps)-1])
	}
	if got.path != beforeRec.ptr.path || got.name != beforeRec.name {
		t.Errorf("path/name changed: %q/%q -> %q/%q", beforeRec.ptr.path, beforeRec.name, got.path, got.name)
	}
	if got.nodeType != FILE {
		t.Errorf("returned node has type %v, want FILE", got.nodeType)
	}

	// no node created or removed, whole-tree structural rules still hold
	if n := takeSnapshot(root).count; n != before.count {
		t.Errorf("node count changed: %d -> %d", before.count, n)
	}
	checkTreeInvariants(t, root)

	// size is the size on disk (independent of the chunker)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
	diskSize := info.Size()
	if got.size != diskSize {
		t.Errorf("file node size %d, disk size %d", got.size, diskSize)
	}
	delta := diskSize - beforeRec.size

	// every node on the chain: same pointer, size shifted by exactly delta, hash
	// changed iff the bytes changed, children list identical (ancestors only)
	onChain := map[string]bool{}
	for i, a := range chain {
		onChain[a.path] = true
		b, ok := before.recs[a.path]
		if !ok {
			t.Errorf("chain node %q was not in the pre-update snapshot", a.path)
			continue
		}
		if a != b.ptr {
			t.Errorf("chain node %q: pointer changed", a.path)
		}
		if a.nodeType != b.nodeType {
			t.Errorf("chain node %q: type %v -> %v", a.path, b.nodeType, a.nodeType)
		}
		if a.size != b.size+delta {
			t.Errorf("chain node %q: size %d, want %d (old %d + delta %d)", a.path, a.size, b.size+delta, b.size, delta)
		}
		switch {
		case changed && a.hash == b.hash:
			t.Errorf("chain node %q: hash did not change although the bytes changed", a.path)
		case !changed && a.hash != b.hash:
			t.Errorf("chain node %q: hash changed although the bytes are identical", a.path)
		}
		if i < len(chain)-1 && !slices.Equal(a.children, b.children) {
			t.Errorf("ancestor %q: children list changed: was %v, now %v", a.path, childNames(b.children), childNames(a.children))
		}
	}

	// the file's own chunk list
	if changed && slices.Equal(got.chunks, beforeRec.chunks) {
		t.Errorf("bytes changed but the chunk list is identical to the old one")
	}
	if !changed && !slices.Equal(got.chunks, beforeRec.chunks) {
		t.Errorf("bytes identical but the chunk list changed")
	}

	// everything off the chain is untouched: same pointer, values, chunks, children
	for p, b := range before.recs {
		if onChain[p] {
			continue
		}
		if d := b.diff(recOf(b.ptr)); d != "" {
			t.Errorf("node %q is not on the chain but was modified: %s", p, d)
		}
	}

	if !changed {
		assertUnchanged(t, tree, before)
	}
}

// ---------------------------------------------------------------------------
// runners
// ---------------------------------------------------------------------------

// doUpdate snapshots the tree, applies mutate to the file on disk, calls Update
// and checks the invariants. Whether the bytes changed is measured on disk
// (before vs after mutate), so the tree must match the disk on entry.
func doUpdate(t *testing.T, tree *Tree, path string, mutate mutator) (*Node, treeSnap, bool) {
	t.Helper()
	before := takeSnapshot(tree.root)

	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	mutate(t, path)
	cur, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	changed := !bytes.Equal(old, cur)

	got, err := tree.Update(path)
	if err != nil {
		t.Fatalf("Update(%q): %v", path, err)
	}
	checkUpdateInvariants(t, tree, before, path, got, changed)
	return got, before, changed
}

// runUpdate builds the tree from fixture, applies mutate to root/rel on disk,
// calls Update, then applies the invariants and the oracle.
func runUpdate(t *testing.T, fixture func(*testing.T, string), rel string, mutate mutator) (*Tree, *Node, treeSnap, string) {
	t.Helper()
	root := newRoot(t)
	fixture(t, root)
	tree := mustBuild(t, root)
	path := relPath(root, rel)

	got, before, _ := doUpdate(t, tree, path, mutate)
	assertMatchesFresh(t, tree, root)
	return tree, got, before, path
}

// callUpdate calls Update and turns a panic into a test failure plus an error
// result, so one bad case does not take the whole test binary down.
func callUpdate(t *testing.T, tree *Tree, path string) (got *Node, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Update(%q) panicked: %v", path, r)
			got, err = nil, fmt.Errorf("panic: %v", r)
		}
	}()
	return tree.Update(path)
}

// ---------------------------------------------------------------------------
// 1. success cases
// ---------------------------------------------------------------------------

func TestUpdateSuccess(t *testing.T) {
	opts := chunker.FastCDCOpts
	multi := 3*opts.MaxSize + opts.MaxSize/2 + 17

	cases := []struct {
		name   string
		rel    string
		mutate mutator
	}{
		// content changes. Fixture sizes: a.txt 100, c.txt 2500, e.txt 7, sub/m.txt 1000,
		// sub/n.txt 0, other/o.txt 321, sub/deep/x.bin 1.5*MaxSize
		{"grow small to bigger", "a.txt", prefixKept("a.txt", 5000)},
		{"grow small to bigger (different bytes)", "a.txt", writeSeeded(501, 5000)},
		{"shrink bigger to small", "c.txt", prefixKept("c.txt", 10)},
		{"same size, different content", "a.txt", writeSeeded(999, 100)},
		{"same size, different content (nested)", "sub/m.txt", writeSeeded(998, 1000)},
		{"same size, different content (multi-chunk)", "sub/deep/x.bin", writeSeeded(997, opts.MaxSize+opts.MaxSize/2)},
		{"to 0 bytes", "c.txt", writeSeeded(1, 0)},
		{"to 0 bytes (nested)", "sub/m.txt", writeSeeded(1, 0)},
		{"from 0 bytes", "sub/n.txt", writeSeeded(5, 500)},
		{"from 0 bytes to multi-chunk", "sub/n.txt", writeSeeded(6, multi)},
		{"to 1 byte", "a.txt", writeSeeded(7, 1)},
		{"from 0 to 1 byte", "sub/n.txt", writeSeeded(8, 1)},
		{"small to multi-chunk", "a.txt", writeSeeded(9, multi)},
		{"small to just under min chunk size", "a.txt", writeSeeded(10, opts.MinSize-1)},
		{"small to exactly max chunk size", "a.txt", writeSeeded(11, opts.MaxSize)},
		{"small to just over max chunk size", "a.txt", writeSeeded(12, opts.MaxSize+1)},
		{"multi-chunk to small", "sub/deep/x.bin", writeSeeded(13, 50)},
		{"multi-chunk to 0 bytes", "sub/deep/x.bin", writeSeeded(13, 0)},
		{"multi-chunk to a longer multi-chunk", "sub/deep/x.bin", writeSeeded(14, multi)},
		{"multi-chunk to a shorter multi-chunk", "sub/deep/x.bin", writeSeeded(15, opts.MaxSize+opts.MaxSize/3)},

		// no-op updates: bytes identical, nothing may change
		{"identical bytes rewritten", "a.txt", rewriteSame()},
		{"identical bytes rewritten (multi-chunk)", "sub/deep/x.bin", rewriteSame()},
		{"identical bytes rewritten (0 bytes)", "sub/n.txt", rewriteSame()},
		{"identical bytes rewritten (put with the same size)", "c.txt", prefixKept("c.txt", 2500)},

		// location: root
		{"root: first file", "a.txt", writeSeeded(21, 333)},
		{"root: middle file", "c.txt", writeSeeded(22, 333)},
		{"root: last file", "e.txt", writeSeeded(23, 333)},
		// location: nested
		{"nested: sub/m.txt", "sub/m.txt", writeSeeded(24, 4242)},
		{"nested: sub/deep/x.bin", "sub/deep/x.bin", writeSeeded(25, 4242)},
		{"nested: other/o.txt", "other/o.txt", writeSeeded(26, 4242)},
		{"nested: last sibling sub/n.txt", "sub/n.txt", writeSeeded(27, 4242)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runUpdate(t, makeFixture, tc.rel, tc.mutate)
		})
	}
}

// first, middle and last file among five siblings, plus a sibling folder that
// sorts before and after them, so the slot of the node in its parent matters.
func TestUpdateSiblingPositions(t *testing.T) {
	for _, rel := range []string{"many/f1", "many/f2", "many/f3", "many/f4", "many/f5"} {
		t.Run(rel, func(t *testing.T) {
			runUpdate(t, makeUpdateFixture, rel, writeSeeded(seedOf(rel)+1, 777))
		})
	}
}

// a 0-byte file hashes as sha256("0"), no chunks.
func TestUpdateToEmptyFileHash(t *testing.T) {
	_, node, _, _ := runUpdate(t, makeFixture, "c.txt", writeSeeded(1, 0))
	if node.size != 0 || len(node.chunks) != 0 {
		t.Errorf("0-byte file: size %d, %d chunks; want 0 and 0", node.size, len(node.chunks))
	}
	want := sha256.Sum256([]byte("0"))
	if node.hash != hex.EncodeToString(want[:]) {
		t.Errorf("0-byte file hash %s, want sha256(\"0\") %s", node.hash, hex.EncodeToString(want[:]))
	}
}

// A same-length edit in the middle of a multi-chunk file. Content-defined
// chunking: every chunk that ends at or before the edit is made only of
// unchanged bytes, so it must keep its offset, size and hash. The edited chunk
// must change.
func TestUpdateMidEditChunkStability(t *testing.T) {
	opts := chunker.FastCDCOpts
	size := 6 * opts.MaxSize
	editPos := 4 * opts.MaxSize

	_, node, before, path := runUpdate(t, makeUpdateFixture, "big.bin", flipByteAt(editPos))
	old := before.recs[path].chunks

	if node.size != int64(size) {
		t.Errorf("size %d, want %d (an edit in place keeps the length)", node.size, size)
	}
	stable := 0
	for i, c := range old {
		if c.Offset+c.Size > editPos {
			break
		}
		stable++
		if i >= len(node.chunks) || node.chunks[i] != c {
			t.Errorf("chunk %d ends before the edit (offset %d, size %d) but changed", i, c.Offset, c.Size)
		}
	}
	if stable < 3 {
		t.Fatalf("only %d chunks end before the edit: the stability check is too weak (%d old chunks)", stable, len(old))
	}
	oldHashes := map[string]bool{}
	for _, c := range old {
		oldHashes[c.Hash] = true
	}
	novel := 0
	for _, c := range node.chunks {
		if !oldHashes[c.Hash] {
			novel++
		}
	}
	if novel == 0 {
		t.Errorf("no chunk hash is new although a byte was flipped")
	}
}

// Appending to a multi-chunk file: all chunks before the old last chunk keep
// their hash (the old last chunk ended at EOF, not at a content-defined cut, so
// it may legitimately grow or be re-cut).
func TestUpdateAppendChunkStability(t *testing.T) {
	opts := chunker.FastCDCOpts
	_, node, before, path := runUpdate(t, makeUpdateFixture, "big.bin", appendRandom(31, 3*opts.MaxSize/2+5))
	old := before.recs[path].chunks

	if len(old) < 3 {
		t.Fatalf("old file has only %d chunks, need at least 3 for a meaningful check", len(old))
	}
	if node.size != before.recs[path].size+int64(3*opts.MaxSize/2+5) {
		t.Errorf("size %d after append", node.size)
	}
	for i := 0; i < len(old)-1; i++ {
		if i >= len(node.chunks) || node.chunks[i] != old[i] {
			t.Errorf("chunk %d (before the old last chunk) changed by an append: was %+v", i, old[i])
		}
	}
	if len(node.chunks) < len(old) {
		t.Errorf("%d chunks after the append, was %d", len(node.chunks), len(old))
	}
}

// ---------------------------------------------------------------------------
// 2. sequences
// ---------------------------------------------------------------------------

// 40 random updates (fixed seed) on random existing files, each checked against
// the invariants and a fresh BuildTree.
func TestUpdateRandomSequence(t *testing.T) {
	opts := chunker.FastCDCOpts
	root := newRoot(t)
	makeUpdateFixture(t, root)
	tree := mustBuild(t, root)

	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	rng := rand.New(rand.NewSource(1234))
	sizes := []int{0, 1, 17, 300, 4096, 20000, opts.MaxSize + 5, 2*opts.MaxSize + 99}

	for i := 0; i < 40; i++ {
		path := files[rng.Intn(len(files))]
		var mutate mutator
		var kind string
		switch rng.Intn(6) {
		case 0:
			kind = "rewrite same"
			mutate = rewriteSame()
		case 1:
			kind = "append"
			mutate = appendRandom(int64(i), sizes[rng.Intn(len(sizes))])
		case 2:
			kind = "flip byte"
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() == 0 {
				mutate = writeSeeded(int64(i), 3) // nothing to flip
				kind = "grow from empty"
			} else {
				mutate = flipByteAt(rng.Intn(int(info.Size())))
			}
		default:
			kind = "fresh content"
			mutate = writeSeeded(int64(1000+i), sizes[rng.Intn(len(sizes))])
		}

		doUpdate(t, tree, path, mutate)
		assertMatchesFresh(t, tree, root)
		if t.Failed() {
			t.Fatalf("stopping at step %d (%s on %s)", i, kind, path)
		}
	}
}

// Update the same file several times in a row; a repeat with identical bytes is a no-op.
func TestUpdateSameFileRepeatedly(t *testing.T) {
	for _, rel := range []string{"a.txt", "sub/deep/x.bin", "sub/n.txt"} {
		t.Run(rel, func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)
			path := relPath(root, rel)

			first, _, changed := doUpdate(t, tree, path, writeSeeded(41, 500))
			if !changed {
				t.Fatalf("first update did not change the bytes: test is broken")
			}
			second, _, changed := doUpdate(t, tree, path, writeSeeded(42, 9000))
			if !changed {
				t.Fatalf("second update did not change the bytes: test is broken")
			}
			third, _, changed := doUpdate(t, tree, path, rewriteSame())
			if changed {
				t.Fatalf("rewriteSame changed the bytes: test is broken")
			}
			if first != second || second != third {
				t.Errorf("Update returned different node pointers for the same file")
			}
			assertMatchesFresh(t, tree, root)
		})
	}
}

// Change a file, update, restore the original bytes, update: the whole tree
// (root hash included) is back to what it was at build time.
func TestUpdateThenRestore(t *testing.T) {
	for _, rel := range []string{"a.txt", "sub/deep/x.bin", "sub/n.txt", "other/o.txt"} {
		t.Run(rel, func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)
			path := relPath(root, rel)
			origSnap := takeSnapshot(tree.root)
			origRootHash := tree.root.hash

			orig, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			_, _, changed := doUpdate(t, tree, path, writeSeeded(51, 6000))
			if !changed {
				t.Fatalf("test is broken: bytes did not change")
			}
			if tree.root.hash == origRootHash {
				t.Errorf("root hash did not change after the update")
			}

			_, _, changed = doUpdate(t, tree, path, restoreBytes(orig))
			if !changed {
				t.Fatalf("test is broken: restore did not change the bytes")
			}
			if tree.root.hash != origRootHash {
				t.Errorf("root hash after restoring the bytes is %s, want the original %s", tree.root.hash, origRootHash)
			}
			assertUnchanged(t, tree, origSnap) // every node, hash, size and chunk list is back
			assertMatchesFresh(t, tree, root)
		})
	}
}

// Update after Insert: a freshly inserted file, and files inside a freshly
// inserted folder. Updating the inserted folder itself must fail.
func TestUpdateAfterInsert(t *testing.T) {
	root := newRoot(t)
	makeFixture(t, root)
	tree := mustBuild(t, root)

	// inserted file
	p := put(t, root, "sub/ins.txt", 300)
	inserted, err := tree.Insert(p)
	if err != nil {
		t.Fatalf("Insert(%q): %v", p, err)
	}
	got, _, _ := doUpdate(t, tree, p, writeSeeded(61, 900))
	if got != inserted {
		t.Errorf("Update returned a different node than the one Insert returned")
	}
	doUpdate(t, tree, p, writeSeeded(62, 0))
	doUpdate(t, tree, p, writeSeeded(63, 3*chunker.FastCDCOpts.MaxSize))
	assertMatchesFresh(t, tree, root)

	// inserted folder with files inside (a.txt 50 B, z.txt 0 B, b/c.txt 3000 B, b/d/e.bin 70000 B, b/empty/)
	proj := newSubtree("proj")(t, root)
	projNode, err := tree.Insert(proj)
	if err != nil {
		t.Fatalf("Insert(%q): %v", proj, err)
	}
	for i, rel := range []string{"proj/a.txt", "proj/z.txt", "proj/b/c.txt", "proj/b/d/e.bin"} {
		doUpdate(t, tree, relPath(root, rel), writeSeeded(int64(70+i), 1500+i))
		assertMatchesFresh(t, tree, root)
		if childByName(tree.root, "proj") != projNode {
			t.Errorf("after updating %s: the inserted folder node is no longer in the tree", rel)
		}
	}

	// the inserted folders themselves cannot be updated
	for _, rel := range []string{"proj", "proj/b", "proj/b/empty"} {
		before := takeSnapshot(tree.root)
		n, err := callUpdate(t, tree, relPath(root, rel))
		if err == nil || n != nil {
			t.Errorf("Update(%s) = (%v, %v), want (nil, error)", rel, n, err)
		}
		assertUnchanged(t, tree, before)
	}
}

// Three files change on disk; Update them in every order. Each step is checked
// against the invariants; the final root hash is the same for every order and
// matches a fresh BuildTree.
func TestUpdateOrderIndependence(t *testing.T) {
	opts := chunker.FastCDCOpts
	edits := []struct {
		rel string
		mut mutator
	}{
		{"a.txt", writeSeeded(81, 333)},
		{"sub/m.txt", writeSeeded(82, 4444)},
		{"sub/deep/x.bin", writeSeeded(83, 2*opts.MaxSize+1)},
	}

	var wantHash string
	for _, perm := range permutations(len(edits)) {
		t.Run(fmt.Sprint(perm), func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)

			for _, e := range edits { // all edits are on disk before the first Update
				e.mut(t, relPath(root, e.rel))
			}
			for _, i := range perm {
				path := relPath(root, edits[i].rel)
				before := takeSnapshot(tree.root)
				got, err := tree.Update(path)
				if err != nil {
					t.Fatalf("Update(%q): %v", path, err)
				}
				checkUpdateInvariants(t, tree, before, path, got, true)
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

// ---------------------------------------------------------------------------
// 3. error cases: error returned, nil node, tree unchanged
// ---------------------------------------------------------------------------

func TestUpdateErrors(t *testing.T) {
	cases := []struct {
		name string
		// setup prepares the disk (the tree was built before this runs) and returns
		// the path to hand to Update.
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

		// in the tree, gone from disk: Stat fails, the result must not be dereferenced
		{"in tree but deleted from disk", func(t *testing.T, root string) string {
			p := filepath.Join(root, "a.txt")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"in tree but deleted from disk (nested)", func(t *testing.T, root string) string {
			p := filepath.Join(root, "sub", "m.txt")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"in tree but deleted from disk (multi-chunk)", func(t *testing.T, root string) string {
			p := filepath.Join(root, "sub", "deep", "x.bin")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"in tree but its whole parent folder is deleted from disk", func(t *testing.T, root string) string {
			if err := os.RemoveAll(filepath.Join(root, "sub")); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(root, "sub", "m.txt")
		}},

		// on disk, never inserted
		{"file on disk but not in the tree", func(t *testing.T, root string) string {
			return put(t, root, "new.txt", 10)
		}},
		{"file on disk but not in the tree (nested, parent in tree)", func(t *testing.T, root string) string {
			return put(t, root, "sub/new.txt", 10)
		}},
		{"file on disk but not in the tree (sorts first)", func(t *testing.T, root string) string {
			return put(t, root, "0.txt", 10)
		}},

		// folders
		{"existing folder with children", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub")
		}},
		{"existing nested folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "deep")
		}},
		{"existing empty folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "emptydir")
		}},

		// the root
		{"the root path itself", func(t *testing.T, root string) string {
			return root
		}},
		{"the root path itself, trailing slash", func(t *testing.T, root string) string {
			return root + string(filepath.Separator)
		}},
		{"the root path itself, trailing /.", func(t *testing.T, root string) string {
			return root + string(filepath.Separator) + "."
		}},
		{"the root path, but disk now has a file there", func(t *testing.T, root string) string {
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
			writeFile(t, root, []byte("now a file"))
			return root
		}},

		// type disagreements between tree and disk
		{"tree has a file, disk has a folder", func(t *testing.T, root string) string {
			p := filepath.Join(root, "a.txt")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mkdir(t, p)
			return p
		}},
		{"tree has a file, disk has a folder (nested)", func(t *testing.T, root string) string {
			p := filepath.Join(root, "sub", "m.txt")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mkdir(t, p)
			return p
		}},
		{"tree has a folder, disk has a file", func(t *testing.T, root string) string {
			p := filepath.Join(root, "sub")
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			writeFile(t, p, []byte("now a file"))
			return p
		}},
		{"tree has a folder, disk has a file (nested)", func(t *testing.T, root string) string {
			p := filepath.Join(root, "sub", "deep")
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			writeFile(t, p, []byte("now a file"))
			return p
		}},
		{"tree has an empty folder, disk has a file", func(t *testing.T, root string) string {
			p := filepath.Join(root, "emptydir")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			writeFile(t, p, []byte("now a file"))
			return p
		}},

		// relative paths: files are in the tree and changed on disk, so a wrongly
		// accepted update would be visible
		{"relative path", func(t *testing.T, root string) string {
			put(t, root, "a.txt", 555)
			t.Chdir(root)
			return "a.txt"
		}},
		{"relative path with ./", func(t *testing.T, root string) string {
			put(t, root, "a.txt", 555)
			t.Chdir(root)
			return "." + string(filepath.Separator) + "a.txt"
		}},
		{"relative path into subfolder", func(t *testing.T, root string) string {
			put(t, root, "sub/m.txt", 555)
			t.Chdir(root)
			return filepath.Join("sub", "m.txt")
		}},

		// outside the root
		{"outside root: sibling folder sharing the root's string prefix", func(t *testing.T, root string) string {
			// root = <tmp>/dir, path = <tmp>/dir2/file
			return put(t, root+"2", "file", 10)
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

		// parents missing from the tree
		{"missing intermediate folder (on disk, not in tree)", func(t *testing.T, root string) string {
			return put(t, root, "newdir/f.txt", 10)
		}},
		{"missing intermediate folder under a nested folder", func(t *testing.T, root string) string {
			return put(t, root, "sub/newdir/f.txt", 10)
		}},
		{"two missing intermediate folders", func(t *testing.T, root string) string {
			return put(t, root, "n1/n2/f.txt", 10)
		}},

		// ancestor is a file in the tree but a folder on disk
		{"parent is a file in the tree (folder on disk)", func(t *testing.T, root string) string {
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

		// chunking fails after every guard passed: nothing may be half-assigned.
		// The file is rewritten bigger first, so a premature size assignment would show.
		{"unreadable file (chmod 000)", func(t *testing.T, root string) string {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file permissions")
			}
			p := put(t, root, "sub/m.txt", 5000)
			t.Cleanup(func() { os.Chmod(p, 0o644) })
			if err := os.Chmod(p, 0o000); err != nil {
				t.Fatal(err)
			}
			return p
		}},
		{"unreadable file (chmod 000), multi-chunk", func(t *testing.T, root string) string {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file permissions")
			}
			p := put(t, root, "sub/deep/x.bin", 50)
			t.Cleanup(func() { os.Chmod(p, 0o644) })
			if err := os.Chmod(p, 0o000); err != nil {
				t.Fatal(err)
			}
			return p
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)
			before := takeSnapshot(tree.root)

			path := tc.setup(t, root)
			got, err := callUpdate(t, tree, path)

			if err == nil {
				t.Errorf("Update(%q) succeeded, want an error", path)
			}
			if got != nil {
				t.Errorf("Update(%q) returned a node together with an error", path)
			}
			assertUnchanged(t, tree, before)
		})
	}
}

// nil *Tree receiver must return an error, not panic.
func TestUpdateNilTree(t *testing.T) {
	root := newRoot(t)
	p := put(t, root, "f.txt", 10)

	var tr *Tree
	got, err := callUpdate(t, tr, p)
	if err == nil {
		t.Errorf("Update on a nil *Tree succeeded, want an error")
	}
	if got != nil {
		t.Errorf("Update on a nil *Tree returned a node")
	}
}

// A tree with no root must refuse to update, not panic.
func TestUpdateNilRoot(t *testing.T) {
	root := newRoot(t)
	p := put(t, root, "f.txt", 10)

	for name, path := range map[string]string{
		"existing file":    p,
		"missing file":     filepath.Join(root, "missing.txt"),
		"folder":           root,
		"empty path":       "",
		"relative to root": "f.txt",
	} {
		t.Run(name, func(t *testing.T) {
			tree := &Tree{}
			got, err := callUpdate(t, tree, path)
			if err == nil {
				t.Errorf("Update(%q) on a tree with a nil root succeeded, want an error", path)
			}
			if got != nil {
				t.Errorf("Update(%q) returned a node together with an error", path)
			}
			if tree.root != nil {
				t.Errorf("tree root is no longer nil")
			}
		})
	}
}

// A failed Update must not poison the tree: a later valid Update still works and
// still matches a fresh build.
func TestUpdateRecoversAfterError(t *testing.T) {
	root := newRoot(t)
	makeFixture(t, root)
	tree := mustBuild(t, root)

	bad := put(t, root, "sub/new.txt", 10) // not in the tree
	if n, err := callUpdate(t, tree, bad); err == nil || n != nil {
		t.Fatalf("Update of a file not in the tree = (%v, %v), want (nil, error)", n, err)
	}
	if err := os.Remove(bad); err != nil {
		t.Fatal(err)
	}

	doUpdate(t, tree, relPath(root, "sub/m.txt"), writeSeeded(91, 2222))
	assertMatchesFresh(t, tree, root)
}

// Several guards in Update are redundant for the outcome (a directory on disk
// is also refused by the tree-node folder guard, by chunkPath failing to read
// it, or by "not found"; walk errors also imply found == false). Without a
// check on WHICH guard fired, deleting one of them goes unnoticed. Each case
// below is built so that exactly one guard is the first to refuse, and the
// error must say so. This pins the wording of those messages on purpose.
func TestUpdateWhichGuardRefuses(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, root string) string
		want  string
	}{
		{"disk folder, tree file: refused before chunking", func(t *testing.T, root string) string {
			p := filepath.Join(root, "a.txt")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			mkdir(t, p)
			return p
		}, "cannot update folders"},
		{"disk folder, tree folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub")
		}, "cannot update folders"},
		{"tree folder, disk file: refused by the tree-node guard", func(t *testing.T, root string) string {
			p := filepath.Join(root, "sub")
			if err := os.RemoveAll(p); err != nil {
				t.Fatal(err)
			}
			writeFile(t, p, []byte("now a file"))
			return p
		}, "cannot update folders"},
		{"root, disk file: refused by the root guard", func(t *testing.T, root string) string {
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
			writeFile(t, root, []byte("now a file"))
			return root
		}, "cannot update root"},
		{"file not in tree: refused by the found check", func(t *testing.T, root string) string {
			return put(t, root, "sub/new.txt", 10)
		}, "could not find node"},
		{"missing intermediate folder: refused by walk", func(t *testing.T, root string) string {
			return put(t, root, "newdir/f.txt", 10)
		}, "not in tree"},
		{"ancestor is a file in the tree: refused by walk", func(t *testing.T, root string) string {
			if err := os.Remove(filepath.Join(root, "sub", "m.txt")); err != nil {
				t.Fatal(err)
			}
			return put(t, root, "sub/m.txt/inner/y.txt", 10)
		}, "is not a folder"},
		{"outside the root: refused by walk", func(t *testing.T, root string) string {
			return put(t, root+"2", "file", 10)
		}, "under the tree root"},
		{"path missing on disk: refused by stat", func(t *testing.T, root string) string {
			return filepath.Join(root, "nope.txt")
		}, "path error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newRoot(t)
			makeFixture(t, root)
			tree := mustBuild(t, root)
			before := takeSnapshot(tree.root)

			path := tc.setup(t, root)
			got, err := callUpdate(t, tree, path)
			if err == nil || got != nil {
				t.Fatalf("Update(%q) = (%v, %v), want (nil, error)", path, got, err)
			}
			// the temp paths contain the test name, so strip them before matching
			msg := strings.ReplaceAll(err.Error(), filepath.Dir(root), "<tmp>")
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error %q does not contain %q: a different guard refused it", msg, tc.want)
			}
			assertUnchanged(t, tree, before)
		})
	}
}
