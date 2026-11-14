package merkle

// Tests for Tree.Delete.
//
// Same approach as the Insert/Update tests (insert_test.go, update_test.go; their
// helpers are reused here, new helpers are prefixed "del"):
//   - Delete only edits the in-memory tree, it never touches the disk. For a
//     successful Delete the tests remove the same path from the disk afterwards,
//     and then the tree must equal a fresh BuildTree (assertMatchesFresh);
//   - direct invariants (checkDeleteInvariants) that do not depend on
//     walk/search/BuildTree;
//   - on any error: (false, err) and the tree is exactly what it was (assertUnchanged).
//
// Paths: one root string (newRoot) is used for BuildTree and for every path
// handed to Delete. Never mix spellings (macOS /var -> /private/var).
//
// Out of scope for now: messy-path ("./", "//", "sub/../") success cases.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/VohraAK/hashsync/internal/chunker"
)

// ---------------------------------------------------------------------------
// fixtures and helpers
// ---------------------------------------------------------------------------

// delFixture is makeUpdateFixture (many/f1..f5, big.bin on top of makeFixture)
// plus a folder with nested subfolders. Root children, sorted:
//
//	a.txt big.bin c.txt e.txt emptydir many other proj sub
//
//	proj/{a.txt, z.txt(0 B), b/c.txt, b/d/e.bin, b/empty/}
func delFixture(t *testing.T, root string) {
	t.Helper()
	makeUpdateFixture(t, root)
	makeSubtree(t, putDir(t, root, "proj"))
}

func delSetup(t *testing.T) (string, *Tree) {
	t.Helper()
	root := newRoot(t)
	delFixture(t, root)
	return root, mustBuild(t, root)
}

// delCall calls Delete and turns a panic into a test failure plus an error
// result, so one bad case does not take the whole test binary down.
func delCall(t *testing.T, tree *Tree, path string) (ok bool, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Delete(%q) panicked: %v", path, r)
			ok, err = false, fmt.Errorf("panic: %v", r)
		}
	}()
	return tree.Delete(path)
}

// delFolderHash recomputes a folder's hash from its children, independently of
// getHashable: sha256 over (name, 0x00, type digit, hash) of each child in order.
func delFolderHash(n *Node) string {
	var sb strings.Builder
	for _, c := range n.children {
		sb.WriteString(c.name)
		sb.WriteString("\x00")
		sb.WriteString(strconv.Itoa(int(c.nodeType)))
		sb.WriteString(c.hash)
	}
	sum := sha256.Sum256([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

// delAssertEmptyFolder: no children, size 0, hash of an empty folder (sha256 of nothing).
func delAssertEmptyFolder(t *testing.T, n *Node) {
	t.Helper()
	if n == nil {
		t.Fatalf("folder node is nil")
	}
	want := sha256.Sum256(nil)
	if len(n.children) != 0 || n.size != 0 {
		t.Errorf("folder %q: %d children, size %d; want 0 and 0", n.path, len(n.children), n.size)
	}
	if n.hash != hex.EncodeToString(want[:]) {
		t.Errorf("folder %q: hash %s, want the hash of an empty folder %s", n.path, n.hash, hex.EncodeToString(want[:]))
	}
}

// delSubtreePaths returns path and every path below it, from the pre-delete snapshot.
func delSubtreePaths(before treeSnap, path string) map[string]bool {
	out := map[string]bool{}
	for p := range before.recs {
		if p == path || strings.HasPrefix(p, path+string(filepath.Separator)) {
			out[p] = true
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// invariants after a successful Delete
// ---------------------------------------------------------------------------

// checkDeleteInvariants verifies, after Delete(path) returned ok with a nil
// error, everything the spec asks for. before is the snapshot taken before the
// call. Nodes are found by linear scan, not by walk (except the one explicit
// "walk no longer finds it" check).
func checkDeleteInvariants(t *testing.T, tree *Tree, before treeSnap, path string, ok bool) {
	t.Helper()
	if !ok {
		t.Errorf("Delete(%q) returned false together with a nil error", path)
	}
	root := tree.root
	if root != before.root {
		t.Fatalf("tree root pointer changed")
	}
	rec, present := before.recs[path]
	if !present {
		t.Fatalf("%q was not in the pre-delete snapshot", path)
	}

	rel, err := filepath.Rel(root.path, path)
	if err != nil {
		t.Fatalf("rel(%q, %q): %v", root.path, path, err)
	}
	comps := strings.Split(rel, string(filepath.Separator))

	// ancestors root..parent, found by linear scan on the tree as it is NOW
	chain := []*Node{root}
	for _, comp := range comps[:len(comps)-1] {
		next := childByName(chain[len(chain)-1], comp)
		if next == nil {
			t.Fatalf("ancestor %q of %q is not in the tree after Delete", comp, path)
		}
		chain = append(chain, next)
	}
	parent := chain[len(chain)-1]
	name := comps[len(comps)-1]

	// the node is gone from its parent
	if childByName(parent, name) != nil {
		t.Errorf("%q is still a child of %q", name, parent.path)
	}
	if slices.Contains(parent.children, rec.ptr) {
		t.Errorf("the deleted node pointer is still in %q children", parent.path)
	}

	// the whole subtree is gone: nothing below it in the tree, walk does not find it
	gone := delSubtreePaths(before, path)
	after := takeSnapshot(root)
	if want := before.count - len(gone); after.count != want {
		t.Errorf("node count %d, want %d (was %d, subtree of %q has %d nodes)", after.count, want, before.count, path, len(gone))
	}
	for p := range gone {
		if _, still := after.recs[p]; still {
			t.Errorf("node %q (inside the deleted subtree) is still in the tree", p)
		}
		if _, _, found, _ := tree.walk(p); found {
			t.Errorf("walk(%q) still finds a node after Delete(%q)", p, path)
		}
	}

	// whole-tree structural rules: sorted children, sizes = sum of children, paths
	checkTreeInvariants(t, root)

	// every ancestor: same pointer, size shrank by exactly the deleted size, hash
	// changed AND equals an independent recomputation, children list = old list
	// minus the deleted node (parent) or identical (the others)
	ancestors := map[string]bool{}
	for _, a := range chain {
		ancestors[a.path] = true
		b, inBefore := before.recs[a.path]
		if !inBefore {
			t.Errorf("ancestor %q was not in the pre-delete snapshot", a.path)
			continue
		}
		if a != b.ptr {
			t.Errorf("ancestor %q: pointer changed", a.path)
		}
		if a.nodeType != FOLDER {
			t.Errorf("ancestor %q: type %v, want FOLDER", a.path, a.nodeType)
		}
		if a.size != b.size-rec.size {
			t.Errorf("ancestor %q: size %d, want %d (old %d - deleted %d)", a.path, a.size, b.size-rec.size, b.size, rec.size)
		}
		if a.hash == b.hash {
			t.Errorf("ancestor %q: hash did not change", a.path)
		}
		if want := delFolderHash(a); a.hash != want {
			t.Errorf("ancestor %q: hash %s, an independent recomputation gives %s", a.path, a.hash, want)
		}
		wantChildren := slices.Clone(b.children)
		if a == parent {
			wantChildren = slices.DeleteFunc(wantChildren, func(c *Node) bool { return c == rec.ptr })
		}
		if !slices.Equal(a.children, wantChildren) {
			t.Errorf("ancestor %q: children are %v, want %v (same pointers, same order)", a.path, childNames(a.children), childNames(wantChildren))
		}
	}

	// everything else is untouched: same pointer, size, hash, chunks, children.
	// This includes the removed nodes themselves: Delete must not rehash them.
	for p, b := range before.recs {
		if ancestors[p] {
			continue
		}
		if d := b.diff(recOf(b.ptr)); d != "" {
			what := "unrelated node"
			if gone[p] {
				what = "removed node"
			}
			t.Errorf("%s %q was modified by Delete: %s", what, p, d)
		}
	}
}

// ---------------------------------------------------------------------------
// runners
// ---------------------------------------------------------------------------

// delStep snapshots the tree, calls Delete (memory only) and checks the
// invariants. It does not touch the disk. Returns the pre-delete snapshot.
func delStep(t *testing.T, tree *Tree, path string) treeSnap {
	t.Helper()
	before := takeSnapshot(tree.root)
	ok, err := delCall(t, tree, path)
	if err != nil {
		t.Fatalf("Delete(%q): %v", path, err)
	}
	checkDeleteInvariants(t, tree, before, path, ok)
	return before
}

// delDo is delStep plus the main oracle: remove the same path from the disk,
// then the tree must equal a fresh BuildTree of root.
func delDo(t *testing.T, tree *Tree, root, path string) treeSnap {
	t.Helper()
	before := delStep(t, tree, path)
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
	assertMatchesFresh(t, tree, root)
	return before
}

// delExpectErr: Delete(path) must return (false, error) and leave the tree exactly as it was.
func delExpectErr(t *testing.T, tree *Tree, path string) error {
	t.Helper()
	before := takeSnapshot(tree.root)
	ok, err := delCall(t, tree, path)
	if err == nil {
		t.Errorf("Delete(%q) succeeded, want an error", path)
	}
	if ok {
		t.Errorf("Delete(%q) returned true together with an error", path)
	}
	assertUnchanged(t, tree, before)
	return err
}

// ---------------------------------------------------------------------------
// 1. success cases
// ---------------------------------------------------------------------------

func TestDeleteSuccess(t *testing.T) {
	cases := []struct {
		name string
		rel  string
	}{
		// top-level files: first, middle, last, multi-chunk
		{"top-level file, first", "a.txt"},
		{"top-level file, multi-chunk", "big.bin"},
		{"top-level file, middle", "c.txt"},
		{"top-level file, last file (folders follow)", "e.txt"},

		// files among siblings
		{"many/f1 first child", "many/f1"},
		{"many/f2", "many/f2"},
		{"many/f3 middle child", "many/f3"},
		{"many/f4", "many/f4"},
		{"many/f5 last child", "many/f5"},
		{"proj/a.txt first child", "proj/a.txt"},
		{"proj/z.txt last child, 0 bytes", "proj/z.txt"},
		{"sub/n.txt last child, 0 bytes", "sub/n.txt"},
		{"sub/m.txt", "sub/m.txt"},

		// deeply nested
		{"deeply nested file", "proj/b/d/e.bin"},
		{"nested multi-chunk file, only child of sub/deep", "sub/deep/x.bin"},

		// only child: the folder ends up empty
		{"only child of other", "other/o.txt"},

		// folders
		{"empty folder", "emptydir"},
		{"nested empty folder", "proj/b/empty"},
		{"folder with a file", "other"},
		{"folder with files", "many"},
		{"folder with nested subfolders", "proj"},
		{"nested folder with subfolders", "proj/b"},
		{"nested folder with a file", "proj/b/d"},
		{"folder as last root child", "sub"},
		{"nested folder with a multi-chunk file", "sub/deep"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, tree := delSetup(t)
			delDo(t, tree, root, relPath(root, tc.rel))
		})
	}
}

// Deleting the only child leaves an empty folder whose size and hash are exactly
// those of a folder that was empty from the start.
func TestDeleteOnlyChildLeavesEmptyFolder(t *testing.T) {
	for _, tc := range []struct{ parent, child string }{
		{"other", "other/o.txt"},
		{"sub/deep", "sub/deep/x.bin"},
		{"proj/b/d", "proj/b/d/e.bin"},
	} {
		t.Run(tc.child, func(t *testing.T) {
			root, tree := delSetup(t)
			delDo(t, tree, root, relPath(root, tc.child))

			parent := tree.root
			for _, comp := range strings.Split(tc.parent, "/") {
				parent = childByName(parent, comp)
				if parent == nil {
					t.Fatalf("folder %q is gone from the tree", tc.parent)
				}
			}
			delAssertEmptyFolder(t, parent)
			if empty := childByName(tree.root, "emptydir"); parent.hash != empty.hash {
				t.Errorf("hash of the emptied folder differs from the hash of emptydir, which was empty from the start")
			}
		})
	}
}

// Delete every child of a folder one by one, in several orders; the folder ends
// up empty. Each step is checked against the invariants and the oracle.
func TestDeleteAllChildrenOneByOne(t *testing.T) {
	orders := map[string][]string{
		"many/forward":  {"f1", "f2", "f3", "f4", "f5"},
		"many/reverse":  {"f5", "f4", "f3", "f2", "f1"},
		"many/outside":  {"f1", "f5", "f2", "f4", "f3"},
		"many/middle":   {"f3", "f2", "f4", "f1", "f5"},
		"proj/forward":  {"a.txt", "b", "z.txt"},
		"proj/reverse":  {"z.txt", "b", "a.txt"},
		"proj/mixed":    {"b", "z.txt", "a.txt"},
		"sub/mixed":     {"deep", "n.txt", "m.txt"},
		"sub/mixed-2":   {"m.txt", "deep", "n.txt"},
		"other/single":  {"o.txt"},
		"root/children": {"a.txt", "big.bin", "c.txt", "e.txt", "emptydir", "many", "other", "proj", "sub"},
		"root/reverse":  {"sub", "proj", "other", "many", "emptydir", "e.txt", "c.txt", "big.bin", "a.txt"},
	}
	names := make([]string, 0, len(orders))
	for n := range orders {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			root, tree := delSetup(t)
			folderRel, _, _ := strings.Cut(name, "/")
			folderPath := root
			if folderRel != "root" {
				folderPath = relPath(root, folderRel)
			}
			for _, child := range orders[name] {
				delDo(t, tree, root, filepath.Join(folderPath, child))
			}

			folder := tree.root
			if folderRel != "root" {
				folder = childByName(tree.root, folderRel)
			}
			delAssertEmptyFolder(t, folder)
			if tree.root == nil {
				t.Fatalf("tree has no root any more")
			}
		})
	}
}

// First, middle and last sibling: the remaining names are exactly the other
// four, in order (explicit expectation, not derived from the tree).
func TestDeleteSiblingPositions(t *testing.T) {
	all := []string{"f1", "f2", "f3", "f4", "f5"}
	for _, gone := range all {
		t.Run(gone, func(t *testing.T) {
			root, tree := delSetup(t)
			delDo(t, tree, root, relPath(root, "many/"+gone))

			var want []string
			for _, n := range all {
				if n != gone {
					want = append(want, n)
				}
			}
			many := childByName(tree.root, "many")
			if got := childNames(many.children); !slices.Equal(got, want) {
				t.Errorf("many children %v, want %v", got, want)
			}
			if want := int64(10 + 20 + 30 + 40 + 50 - 10*(slices.Index(all, gone)+1)); many.size != want {
				t.Errorf("many size %d, want %d", many.size, want)
			}
		})
	}
}

// Every ancestor shrinks by exactly the deleted node's size; hard-coded numbers
// from the fixture (sub/m.txt 1000 B, sub/n.txt 0 B, sub/deep/x.bin 1.5*MaxSize).
func TestDeleteAncestorSizesShrink(t *testing.T) {
	x := int64(chunker.FastCDCOpts.MaxSize + chunker.FastCDCOpts.MaxSize/2)

	root, tree := delSetup(t)
	rootBefore := tree.root.size
	sub := childByName(tree.root, "sub")
	if sub.size != 1000+x {
		t.Fatalf("fixture changed: sub size %d, want %d", sub.size, 1000+x)
	}

	delDo(t, tree, root, relPath(root, "sub/deep/x.bin"))

	deep := childByName(sub, "deep")
	if deep.size != 0 {
		t.Errorf("sub/deep size %d, want 0", deep.size)
	}
	if sub.size != 1000 {
		t.Errorf("sub size %d, want 1000", sub.size)
	}
	if tree.root.size != rootBefore-x {
		t.Errorf("root size %d, want %d", tree.root.size, rootBefore-x)
	}

	// a whole subtree: the ancestors lose the folder's total size
	rootBefore = tree.root.size
	delDo(t, tree, root, relPath(root, "sub"))
	if tree.root.size != rootBefore-1000 {
		t.Errorf("root size %d after deleting sub, want %d", tree.root.size, rootBefore-1000)
	}
}

// Documents the "no disk check" decision: Delete trusts the caller. A node that
// is still on disk is removed from the tree anyway, and the tree then
// intentionally differs from a fresh build until the disk catches up.
func TestDeleteDoesNotCheckDisk(t *testing.T) {
	for _, rel := range []string{"a.txt", "many/f3", "sub/deep/x.bin", "sub", "proj/b", "emptydir"} {
		t.Run(rel, func(t *testing.T) {
			root, tree := delSetup(t)
			path := relPath(root, rel)

			delStep(t, tree, path)

			if _, err := os.Stat(path); err != nil {
				t.Fatalf("Delete touched the disk: %v", err)
			}
			fresh := mustBuild(t, root)
			if diffNodes(tree.root, fresh.root) == "" {
				t.Errorf("tree equals a fresh build although %s is still on disk: Delete did not remove it from the tree", rel)
			}

			// once the disk catches up, they agree again
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			assertMatchesFresh(t, tree, root)
		})
	}
}

// The removed node is dropped as it is: Delete must not rehash it (a rehash of
// the removed node is invisible when its fields are consistent, so this test
// makes them stale on purpose and checks they stay stale).
func TestDeleteLeavesRemovedNodeUntouched(t *testing.T) {
	for _, rel := range []string{"a.txt", "many/f3", "sub/deep/x.bin", "emptydir", "proj", "proj/b"} {
		t.Run(rel, func(t *testing.T) {
			root, tree := delSetup(t)
			path := relPath(root, rel)

			snap := takeSnapshot(tree.root)
			node := snap.recs[path].ptr
			node.hash = "stale-hash-set-by-the-test"
			if node.nodeType == FOLDER {
				for _, c := range node.children { // stale inside the subtree too
					c.hash = "stale-hash-set-by-the-test"
				}
			}

			delStep(t, tree, path) // checkDeleteInvariants: removed nodes unchanged
			if node.hash != "stale-hash-set-by-the-test" {
				t.Errorf("the removed node was rehashed: hash is now %s", node.hash)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 2. error cases: (false, error), tree unchanged
// ---------------------------------------------------------------------------

func TestDeleteErrors(t *testing.T) {
	sep := string(filepath.Separator)
	cases := []struct {
		name  string
		setup func(t *testing.T, root string) string
	}{
		// missing, parent exists
		{"missing top-level path", func(t *testing.T, root string) string {
			return filepath.Join(root, "nope.txt")
		}},
		{"missing top-level path, sorts before everything", func(t *testing.T, root string) string {
			return filepath.Join(root, "0.txt")
		}},
		{"missing top-level path, sorts after everything", func(t *testing.T, root string) string {
			return filepath.Join(root, "zzz")
		}},
		{"missing top-level path, prefix of an existing name", func(t *testing.T, root string) string {
			return filepath.Join(root, "su")
		}},
		{"missing top-level path, existing name plus a suffix", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub.txt")
		}},
		{"missing nested path, parent exists", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "nope.txt")
		}},
		{"missing nested path, between siblings", func(t *testing.T, root string) string {
			return filepath.Join(root, "many", "f25")
		}},
		{"missing deeply nested path, parent exists", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "deep", "nope.bin")
		}},
		{"on disk but never inserted", func(t *testing.T, root string) string {
			return put(t, root, "sub/new.txt", 10)
		}},

		// missing middle folder
		{"missing middle folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "newdir", "f.txt")
		}},
		{"missing middle folder under a nested folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "newdir", "f.txt")
		}},
		{"two missing middle folders", func(t *testing.T, root string) string {
			return filepath.Join(root, "n1", "n2", "f.txt")
		}},

		// a file used as a folder
		{"file used as a folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "a.txt", "x")
		}},
		{"nested file used as a folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "m.txt", "x")
		}},
		{"file used as a folder, deeper path", func(t *testing.T, root string) string {
			return filepath.Join(root, "sub", "m.txt", "inner", "y.txt")
		}},
		{"multi-chunk file used as a folder", func(t *testing.T, root string) string {
			return filepath.Join(root, "big.bin", "x")
		}},

		// outside the root
		{"outside root: the parent of the root", func(t *testing.T, root string) string {
			return filepath.Dir(root)
		}},
		{"outside root: ..", func(t *testing.T, root string) string {
			return root + sep + ".."
		}},
		{"outside root: file next to the root", func(t *testing.T, root string) string {
			return put(t, filepath.Dir(root), "outside.txt", 10)
		}},
		{"outside root: sibling folder sharing the root's string prefix", func(t *testing.T, root string) string {
			// root = <tmp>/dir, path = <tmp>/dir2/file
			return put(t, root+"2", "file", 10)
		}},
		{"outside root: sibling folder sharing the root's string prefix, folder itself", func(t *testing.T, root string) string {
			return putDir(t, filepath.Dir(root), "dir2")
		}},
		{"outside root: escapes via ..", func(t *testing.T, root string) string {
			put(t, filepath.Dir(root), "escaped.txt", 10)
			return root + "/sub/../../escaped.txt"
		}},

		// relative paths: nodes with these names exist under the root, so a wrongly
		// accepted path would be visible as a removed node
		{"relative path", func(t *testing.T, root string) string {
			t.Chdir(root)
			return "a.txt"
		}},
		{"relative path with ./", func(t *testing.T, root string) string {
			t.Chdir(root)
			return "." + sep + "a.txt"
		}},
		{"relative path into subfolder", func(t *testing.T, root string) string {
			t.Chdir(root)
			return filepath.Join("sub", "m.txt")
		}},
		{"relative path, folder", func(t *testing.T, root string) string {
			t.Chdir(root)
			return "sub"
		}},
		{"relative path, not chdir'd", func(t *testing.T, root string) string {
			return "a.txt"
		}},
		{"empty path", func(t *testing.T, root string) string {
			return ""
		}},
		{"dot", func(t *testing.T, root string) string {
			t.Chdir(root)
			return "."
		}},

		// the root itself, in several spellings
		{"the root", func(t *testing.T, root string) string {
			return root
		}},
		{"the root, trailing slash", func(t *testing.T, root string) string {
			return root + sep
		}},
		{"the root, double trailing slash", func(t *testing.T, root string) string {
			return root + sep + sep
		}},
		{"the root, trailing /.", func(t *testing.T, root string) string {
			return root + sep + "."
		}},
		{"the root, via a child and ..", func(t *testing.T, root string) string {
			return root + "/sub/.."
		}},
		{"the root, via ./", func(t *testing.T, root string) string {
			return root + "/./"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, tree := delSetup(t)
			path := tc.setup(t, root)
			delExpectErr(t, tree, path)
		})
	}
}

// Missing top-level path: its parent is the root, so walk returns chain = [root]
// and found = false. The "not found" check must come BEFORE the root check,
// otherwise a missing top-level file is reported as an attempt to delete the root.
func TestDeleteMissingTopLevelIsNotRoot(t *testing.T) {
	_, tree := delSetup(t)
	root := tree.root.path

	for _, name := range []string{"nope.txt", "0.txt", "zzz", "su"} {
		path := filepath.Join(root, name)
		err := delExpectErr(t, tree, path)
		if err == nil {
			continue
		}
		// This is the only wording assertion in this file; it pins the message on
		// purpose, because "not found" and "root" are indistinguishable otherwise
		// (both give an error, a false and an unchanged tree). The temp path is
		// stripped first, it contains the test name.
		msg := strings.ReplaceAll(err.Error(), filepath.Dir(root), "<tmp>")
		if strings.Contains(strings.ToLower(msg), "root") {
			t.Errorf("Delete(%q): error %q talks about the root; a missing top-level path is not a root delete", name, msg)
		}
	}

	// and the real root delete is still refused
	delExpectErr(t, tree, root)
}

// nil *Tree receiver must return an error, not panic.
func TestDeleteNilTree(t *testing.T) {
	root := newRoot(t)
	p := put(t, root, "f.txt", 10)

	var tr *Tree
	ok, err := delCall(t, tr, p)
	if err == nil {
		t.Errorf("Delete on a nil *Tree succeeded, want an error")
	}
	if ok {
		t.Errorf("Delete on a nil *Tree returned true")
	}
}

// A tree with no root must refuse to delete, not panic.
func TestDeleteNilRoot(t *testing.T) {
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
			ok, err := delCall(t, tree, path)
			if err == nil {
				t.Errorf("Delete(%q) on a tree with a nil root succeeded, want an error", path)
			}
			if ok {
				t.Errorf("Delete(%q) returned true together with an error", path)
			}
			if tree.root != nil {
				t.Errorf("tree root is no longer nil")
			}
		})
	}
}

// The same path deleted twice: the first call succeeds, the second errors and
// leaves the tree as the first call left it. Also a child of a deleted folder.
func TestDeleteTwice(t *testing.T) {
	for _, tc := range []struct{ first, second string }{
		{"a.txt", "a.txt"},
		{"many/f3", "many/f3"},
		{"sub/deep/x.bin", "sub/deep/x.bin"},
		{"emptydir", "emptydir"},
		{"proj", "proj"},
		{"sub", "sub/m.txt"},           // child of a deleted folder
		{"sub", "sub/deep/x.bin"},      // deeper descendant
		{"proj/b", "proj/b/empty"},     // nested folder, child
		{"other/o.txt", "other/o.txt"}, // only child, then again
	} {
		t.Run(tc.first+" then "+tc.second, func(t *testing.T) {
			root, tree := delSetup(t)
			delDo(t, tree, root, relPath(root, tc.first))

			delExpectErr(t, tree, relPath(root, tc.second))
			assertMatchesFresh(t, tree, root) // nothing moved while it errored
		})
	}
}

// A failed Delete must not poison the tree: a later valid Delete still works and
// still matches a fresh build.
func TestDeleteRecoversAfterError(t *testing.T) {
	root, tree := delSetup(t)

	delExpectErr(t, tree, filepath.Join(root, "sub", "nope.txt")) // missing
	delExpectErr(t, tree, root)                                   // the root
	delExpectErr(t, tree, filepath.Join(root, "a.txt", "x"))      // file used as a folder
	delExpectErr(t, tree, filepath.Dir(root))                     // outside
	assertMatchesFresh(t, tree, root)

	delDo(t, tree, root, relPath(root, "sub/m.txt"))
	delExpectErr(t, tree, relPath(root, "sub/m.txt")) // again
	delDo(t, tree, root, relPath(root, "many/f2"))
	assertMatchesFresh(t, tree, root)
}

// ---------------------------------------------------------------------------
// 3. sequences
// ---------------------------------------------------------------------------

// Delete a node, put the identical content back on disk, Insert the same path:
// the tree (root hash included) is back to what it was at build time. The node
// is parked outside the root with Rename so folders come back byte for byte.
func TestDeleteThenInsertSamePath(t *testing.T) {
	for _, rel := range []string{
		"many/f3", "a.txt", "big.bin", "sub/deep/x.bin", "other/o.txt", // files, only child
		"emptydir", "sub", "proj", "proj/b", "many", // folders
	} {
		t.Run(rel, func(t *testing.T) {
			root, tree := delSetup(t)
			path := relPath(root, rel)
			orig := mustBuild(t, root)
			origRootHash := tree.root.hash
			stash := filepath.Join(filepath.Dir(root), "stash")

			delStep(t, tree, path)
			if err := os.Rename(path, stash); err != nil {
				t.Fatal(err)
			}
			assertMatchesFresh(t, tree, root)
			if tree.root.hash == origRootHash {
				t.Errorf("root hash did not change after the delete")
			}

			if err := os.Rename(stash, path); err != nil {
				t.Fatal(err)
			}
			before := takeSnapshot(tree.root)
			got, err := tree.Insert(path)
			if err != nil {
				t.Fatalf("Insert(%q) after Delete: %v", path, err)
			}
			checkInsertInvariants(t, tree, before, path, got)

			if tree.root.hash != origRootHash {
				t.Errorf("root hash after delete+insert is %s, want the original %s", tree.root.hash, origRootHash)
			}
			if d := diffNodes(tree.root, orig.root); d != "" {
				t.Errorf("tree after delete+insert differs from the tree built at the start: %s", d)
			}
			assertMatchesFresh(t, tree, root)
		})
	}
}

// Delete a file from the tree, change it on disk (still there), then Update it:
// the tree no longer has it, so Update errors and the tree stays as the Delete left it.
func TestDeleteThenUpdateErrors(t *testing.T) {
	for _, rel := range []string{"a.txt", "many/f2", "sub/deep/x.bin", "other/o.txt"} {
		t.Run(rel, func(t *testing.T) {
			root, tree := delSetup(t)
			path := relPath(root, rel)

			delStep(t, tree, path)
			writeFile(t, path, randBytes(777, 4321)) // on disk, changed, not in the tree

			before := takeSnapshot(tree.root)
			n, err := callUpdate(t, tree, path)
			if err == nil || n != nil {
				t.Errorf("Update(%s) after Delete = (%v, %v), want (nil, error)", rel, n, err)
			}
			assertUnchanged(t, tree, before)

			// also with the file gone from disk
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if n, err := callUpdate(t, tree, path); err == nil || n != nil {
				t.Errorf("Update(%s) after Delete and removal = (%v, %v), want (nil, error)", rel, n, err)
			}
			assertUnchanged(t, tree, before)
			assertMatchesFresh(t, tree, root)
		})
	}
}

// delete A then B ends in the same tree as delete B then A (same root hash, and
// both equal a fresh build); every step is checked on its own.
func TestDeleteOrderIndependence(t *testing.T) {
	pairs := [][2]string{
		{"many/f1", "many/f5"},
		{"many/f2", "many/f3"}, // adjacent siblings
		{"a.txt", "sub/deep/x.bin"},
		{"a.txt", "e.txt"},
		{"other", "emptydir"},
		{"proj/b/d/e.bin", "proj/a.txt"},
		{"sub/m.txt", "sub/deep"},
		{"proj/b", "proj/z.txt"},
		{"sub", "proj"},
	}

	run := func(t *testing.T, first, second string) (string, int64) {
		root, tree := delSetup(t)
		delDo(t, tree, root, relPath(root, first))
		delDo(t, tree, root, relPath(root, second))
		return tree.root.hash, tree.root.size
	}

	for _, p := range pairs {
		a, b := p[0], p[1]
		// a pair where one path is inside the other is not symmetric: the second
		// delete finds nothing. Skip it here, TestDeleteTwice covers that case.
		if strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/") {
			continue
		}
		t.Run(a+" and "+b, func(t *testing.T) {
			hAB, sAB := run(t, a, b)
			hBA, sBA := run(t, b, a)
			if hAB != hBA {
				t.Errorf("root hash after A,B is %s, after B,A is %s", hAB, hBA)
			}
			if sAB != sBA {
				t.Errorf("root size after A,B is %d, after B,A is %d", sAB, sBA)
			}
		})
	}
}

// 60 random steps (fixed seed): about 60% Delete of a random existing node (file
// or folder, any depth), the rest Insert of a new file or folder into a random
// existing folder. The disk is the source of truth; after every step the tree
// must match a fresh BuildTree, and each step passes its own invariants.
func TestDeleteRandomSequenceWithInserts(t *testing.T) {
	opts := chunker.FastCDCOpts
	root, tree := delSetup(t)

	rng := rand.New(rand.NewSource(4321))
	sizes := []int{0, 1, 17, 300, 4096, 20000, opts.MaxSize + 5}
	deletes, inserts := 0, 0

	for i := 0; i < 60; i++ {
		snap := takeSnapshot(tree.root)
		var nodes, folders []string // sorted: map order must not leak into the run
		for p, r := range snap.recs {
			if r.nodeType == FOLDER {
				folders = append(folders, p)
			}
			if p != root {
				nodes = append(nodes, p)
			}
		}
		sort.Strings(nodes)
		sort.Strings(folders)

		if len(nodes) > 0 && rng.Intn(100) < 60 {
			path := nodes[rng.Intn(len(nodes))]
			delDo(t, tree, root, path)
			deletes++
			if t.Failed() {
				t.Fatalf("stopping at step %d (Delete %s)", i, path)
			}
			continue
		}

		parent := folders[rng.Intn(len(folders))]
		path := filepath.Join(parent, fmt.Sprintf("ins%02d", i))
		switch rng.Intn(3) {
		case 0:
			path += ".bin"
			writeFile(t, path, randBytes(int64(i), sizes[rng.Intn(len(sizes))]))
		case 1:
			mkdir(t, path)
			makeSubtree(t, path)
		default:
			mkdir(t, path)
		}
		got, err := tree.Insert(path)
		if err != nil {
			t.Fatalf("step %d: Insert(%q): %v", i, path, err)
		}
		checkInsertInvariants(t, tree, snap, path, got)
		assertMatchesFresh(t, tree, root)
		inserts++
		if t.Failed() {
			t.Fatalf("stopping at step %d (Insert %s)", i, path)
		}
	}
	if deletes < 10 || inserts < 10 {
		t.Errorf("random sequence is too one-sided: %d deletes, %d inserts", deletes, inserts)
	}
}
