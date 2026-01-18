// Copyright 2022 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package file

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/gobwas/glob"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/stretchr/testify/require"
)

func TestBrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(testFile, []byte("some dummy data"), os.ModePerm))
	testDir := filepath.Join(dir, "testdir")
	require.NoError(t, os.Mkdir(testDir, os.ModePerm))
	testFile2 := filepath.Join(testDir, "testfile2")
	require.NoError(t, os.WriteFile(testFile2, []byte("more dummy data"), os.ModePerm))

	symTestFile := filepath.Join(dir, "symtestfile")
	require.NoError(t, os.Symlink(testFile, symTestFile))
	symTestDir := filepath.Join(dir, "symTestDir")
	require.NoError(t, os.Symlink(testDir, symTestDir))

	dirHash := make([]glob.Glob, 0)

	_, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)

	// remove the symlinks and make sure we don't get an error back
	require.NoError(t, os.RemoveAll(testDir))
	require.NoError(t, os.RemoveAll(testFile))
	_, err = RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
}

func TestSymlinkCycle(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "testfile")
	require.NoError(t, os.WriteFile(testFile, []byte("some dummy data"), os.ModePerm))
	symTestFile := filepath.Join(dir, "symtestfile")
	require.NoError(t, os.Symlink(testFile, symTestFile))
	symTestDir := filepath.Join(dir, "symTestDir")
	require.NoError(t, os.Symlink(dir, symTestDir))

	dirHash := make([]glob.Glob, 0)

	// if a symlink cycle weren't properly handled this would be an infinite loop
	_, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
}

func TestParallelHashing(t *testing.T) {
	dir := t.TempDir()

	// Create multiple files with different content
	numFiles := 100
	for i := 0; i < numFiles; i++ {
		fileName := filepath.Join(dir, "file"+string(rune('a'+i%26))+string(rune('0'+i/26)))
		content := []byte("content for file " + fileName)
		require.NoError(t, os.WriteFile(fileName, content, os.ModePerm))
	}

	// Create subdirectories with files
	subDir := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(subDir, os.ModePerm))
	for i := 0; i < 10; i++ {
		fileName := filepath.Join(subDir, "subfile"+string(rune('0'+i)))
		require.NoError(t, os.WriteFile(fileName, []byte("subdir content"), os.ModePerm))
	}

	dirHash := make([]glob.Glob, 0)

	// Test that parallel hashing works correctly
	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)

	// Verify we got all files
	totalExpectedFiles := numFiles + 10 // main files + subdir files
	require.Len(t, artifacts, totalExpectedFiles, "Should have hashed all files")

	// Verify all artifacts have valid digests
	for path, digestSet := range artifacts {
		require.NotEmpty(t, digestSet, "File %s should have a digest", path)
		for _, digest := range digestSet {
			require.NotEmpty(t, digest, "Digest for %s should not be empty", path)
		}
	}

	// Run again and verify consistency
	artifacts2, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
	require.Len(t, artifacts2, totalExpectedFiles)

	// Verify identical results
	for path, digestSet := range artifacts {
		digestSet2, ok := artifacts2[path]
		require.True(t, ok, "File %s should exist in second run", path)
		require.True(t, digestSet.Equal(digestSet2), "Digests for %s should match between runs", path)
	}
}

func TestParallelHashingWithBaseArtifacts(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	testFile1 := filepath.Join(dir, "file1")
	testFile2 := filepath.Join(dir, "file2")
	require.NoError(t, os.WriteFile(testFile1, []byte("content1"), os.ModePerm))
	require.NoError(t, os.WriteFile(testFile2, []byte("content2"), os.ModePerm))

	dirHash := make([]glob.Glob, 0)

	// Get initial artifacts
	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
	require.Len(t, artifacts, 2)

	// Run again with base artifacts - should return empty since nothing changed
	artifacts2, err := RecordArtifacts(dir, artifacts, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
	require.Len(t, artifacts2, 0, "Should return empty map when files haven't changed")

	// Modify one file and run again
	require.NoError(t, os.WriteFile(testFile1, []byte("modified content"), os.ModePerm))
	artifacts3, err := RecordArtifacts(dir, artifacts, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
	require.NoError(t, err)
	require.Len(t, artifacts3, 1, "Should only return the modified file")
	_, hasFile1 := artifacts3["file1"]
	require.True(t, hasFile1, "Should contain the modified file")
}

func BenchmarkRecordArtifacts(b *testing.B) {
	dir := b.TempDir()

	// Create many files for benchmarking
	numFiles := 500
	for i := 0; i < numFiles; i++ {
		fileName := filepath.Join(dir, "benchfile_"+string(rune('a'+i%26))+string(rune('a'+i/26%26)))
		// Create files with some content to hash
		content := make([]byte, 1024) // 1KB files
		for j := range content {
			content[j] = byte(i + j)
		}
		if err := os.WriteFile(fileName, content, os.ModePerm); err != nil {
			b.Fatal(err)
		}
	}

	dirHash := make([]glob.Glob, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, dirHash)
		if err != nil {
			b.Fatal(err)
		}
	}
}
