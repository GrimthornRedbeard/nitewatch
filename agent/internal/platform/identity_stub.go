//go:build !windows

package platform

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// FileIdentity is everything the machine can say about a program file. See the
// Windows implementation for the full account; off Windows there is no version
// resource to read, so only the hash and size are available.
type FileIdentity struct {
	Path        string `json:"path"`
	SizeBytes   int64  `json:"sizeBytes,omitempty"`
	SHA256      string `json:"sha256,omitempty"`
	Company     string `json:"company,omitempty"`
	Product     string `json:"product,omitempty"`
	FileVersion string `json:"fileVersion,omitempty"`
	Description string `json:"description,omitempty"`
	Err         string `json:"error,omitempty"`
}

func Identify(path string) FileIdentity {
	id := FileIdentity{Path: path}
	if path == "" {
		id.Err = "no path"
		return id
	}
	st, err := os.Stat(path)
	if err != nil {
		id.Err = "the file could not be read: " + err.Error()
		return id
	}
	id.SizeBytes = st.Size()
	f, err := os.Open(path)
	if err != nil {
		id.Err = "the file could not be read: " + err.Error()
		return id
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		id.Err = "the file could not be read: " + err.Error()
		return id
	}
	id.SHA256 = hex.EncodeToString(h.Sum(nil))
	return id
}
