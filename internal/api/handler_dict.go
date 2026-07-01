package api

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

type DictEntry struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Size     int    `json:"size_bytes"`
	Preview  string `json:"preview"`
}

func (s *Server) ListDicts(c *gin.Context) {
	baseDir := defaultDictDir()
	entries := []DictEntry{}

	entriesList, _ := os.ReadDir(baseDir)
	for _, entry := range entriesList {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		content, err := os.ReadFile(filepath.Join(baseDir, entry.Name()))
		if err != nil {
			continue
		}
		lines := strings.Split(string(content), "\n")
		preview := ""
		if len(lines) > 0 {
			preview = strings.TrimSpace(lines[0])
		}
		entries = append(entries, DictEntry{
			Name:     entry.Name(),
			Category: dictCategory(entry.Name()),
			Size:     int(info.Size()),
			Preview:  preview,
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	c.JSON(http.StatusOK, gin.H{"dicts": entries, "total": len(entries)})
}

func (s *Server) GetDict(c *gin.Context) {
	name := c.Param("name")
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dict name"})
		return
	}

	path := filepath.Join(defaultDictDir(), name)
	if !strings.HasSuffix(path, ".txt") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only .txt files allowed"})
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dict not found"})
		return
	}

	lines := strings.Split(string(content), "\n")
	words := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			words = append(words, line)
		}
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "words": words, "count": len(words)})
}

func (s *Server) AppendDict(c *gin.Context) {
	name := c.Param("name")
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dict name"})
		return
	}

	path := filepath.Join(defaultDictDir(), name)
	if !strings.HasSuffix(path, ".txt") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only .txt files allowed"})
		return
	}

	var req struct {
		Entries []string `json:"entries"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Entries) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "entries array required"})
		return
	}

	// Ensure dir exists
	os.MkdirAll(defaultDictDir(), 0755)

	// Read existing to dedup
	existing := map[string]bool{}
	if data, err := os.ReadFile(path); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if w := strings.TrimSpace(line); w != "" {
				existing[w] = true
			}
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer f.Close()

	added := 0
	for _, entry := range req.Entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || existing[entry] {
			continue
		}
		f.WriteString(entry + "\n")
		existing[entry] = true
		added++
	}

	c.JSON(http.StatusOK, gin.H{"name": name, "added": added})
}

func (s *Server) DeleteDict(c *gin.Context) {
	name := c.Param("name")
	if strings.Contains(name, "..") || strings.Contains(name, "/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid dict name"})
		return
	}

	path := filepath.Join(defaultDictDir(), name)
	if err := os.Remove(path); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "dict not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "dict deleted", "name": name})
}

func defaultDictDir() string {
	dir := os.Getenv("WEAVE_DICT_DIR")
	if dir == "" {
		dir = "data/dicts"
	}
	return dir
}

func dictCategory(name string) string {
	switch {
	case strings.Contains(name, "port"):
		return "port"
	case strings.Contains(name, "path") || strings.Contains(name, "dir") || strings.Contains(name, "file"):
		return "path"
	case strings.Contains(name, "domain") || strings.Contains(name, "sub"):
		return "domain"
	default:
		return "other"
	}
}

