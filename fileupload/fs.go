package fileupload

import (
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
)

type fs struct {
	dir string
}

func (fs *fs) fetch(resp http.ResponseWriter, req *http.Request, filename string) {
	http.ServeFile(resp, req, filepath.Join(fs.dir, filename))
}

func (fs *fs) store(r io.Reader, mimeType string) (filename string, err error) {
	var ext string
	if mimeType != "" {
		exts, _ := mime.ExtensionsByType(mimeType)
		if len(exts) > 0 {
			ext = exts[0]
		}
	}

	var f *os.File
	for i := 0; i < 100; i++ {
		filebase, err := generateToken()
		if err != nil {
			return "", fmt.Errorf("failed to generate file base: %v", err)
		}

		filename = filebase + ext
		f, err = os.OpenFile(filepath.Join(fs.dir, filename), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return "", fmt.Errorf("failed to open file: %v", err)
		}
	}
	if f == nil {
		return "", fmt.Errorf("failed to pick filename")
	}
	defer f.Close()

	if _, err := io.Copy(f, r); err != nil {
		return "", fmt.Errorf("failed to write file: %v", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("failed to close file: %v", err)
	}

	return filename, nil
}
