package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type ChangeEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	Hostname   string    `json:"hostname"`
	Package    string    `json:"package"`
	OldVersion string    `json:"old_version,omitempty"`
	NewVersion string    `json:"new_version,omitempty"`
	Action     string    `json:"action"` // "ADDED", "REMOVED", "MODIFIED"
}

const (
	maxHistoryBytes   = 16 << 20
	maxHistoryBackups = 3
)

type HistoryManager struct {
	mu       sync.RWMutex
	filePath string
}

func NewHistoryManager(dataPath string) *HistoryManager {
	if err := os.MkdirAll(dataPath, 0750); err != nil {
		log.Printf("Failed to create data directory %s: %v", dataPath, err)
	}
	return &HistoryManager{filePath: filepath.Join(dataPath, "history.jsonl")}
}

func (hm *HistoryManager) RecordChanges(events []ChangeEvent) {
	if len(events) == 0 {
		return
	}
	hm.mu.Lock()
	defer hm.mu.Unlock()

	if info, err := os.Stat(hm.filePath); err == nil && info.Size() > maxHistoryBytes {
		if err := hm.rotate(); err != nil {
			log.Printf("Failed to rotate history file: %v", err)
		}
	}

	f, err := os.OpenFile(hm.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		log.Printf("Failed to open history file: %v", err)
		return
	}
	defer func() { _ = f.Close() }()

	for _, evt := range events {
		data, err := json.Marshal(evt)
		if err != nil {
			continue
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			log.Printf("Failed to write history event: %v", err)
			return
		}
	}
}

// rotate keeps a bounded number of old history files. Caller holds the lock.
func (hm *HistoryManager) rotate() error {
	for i := maxHistoryBackups; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", hm.filePath, i)
		dst := fmt.Sprintf("%s.%d", hm.filePath, i+1)
		if _, err := os.Stat(src); err == nil {
			if err := os.Rename(src, dst); err != nil {
				return err
			}
		}
	}
	return os.Rename(hm.filePath, hm.filePath+".1")
}

// eventHeap is a min-heap by timestamp. It lets GetHistory keep only the newest
// N events without loading an unbounded file into memory.
type eventHeap []ChangeEvent

func (h eventHeap) Len() int           { return len(h) }
func (h eventHeap) Less(i, j int) bool { return h[i].Timestamp.Before(h[j].Timestamp) }
func (h eventHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *eventHeap) Push(x any)        { *h = append(*h, x.(ChangeEvent)) }
func (h *eventHeap) Pop() any {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func (hm *HistoryManager) GetHistory(hostname, pkgName string, limit int) []ChangeEvent {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	f, err := os.Open(hm.filePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		log.Printf("Failed to read history file: %v", err)
		return nil
	}
	defer func() { _ = f.Close() }()

	keep := eventHeap{}
	heap.Init(&keep)

	// Pre-filter on the raw JSON line so irrelevant events are never unmarshalled.
	// The exact EqualFold checks below still run after unmarshalling, so this can
	// only skip lines that could never match (no false negatives).
	hostFilter := []byte(strings.ToLower(hostname))
	pkgFilter := []byte(strings.ToLower(pkgName))
	hostASCII := isASCII(hostname)
	pkgASCII := isASCII(pkgName)

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if hostname != "" && hostASCII && !containsFoldASCII(line, hostFilter) {
			continue
		}
		if pkgName != "" && pkgASCII && !containsFoldASCII(line, pkgFilter) {
			continue
		}
		var evt ChangeEvent
		if err := json.Unmarshal(line, &evt); err != nil {
			continue
		}
		if hostname != "" && !strings.EqualFold(evt.Hostname, hostname) {
			continue
		}
		if pkgName != "" && !strings.EqualFold(evt.Package, pkgName) {
			continue
		}
		if limit > 0 && keep.Len() >= limit {
			if !evt.Timestamp.After(keep[0].Timestamp) {
				continue
			}
			heap.Pop(&keep)
		}
		heap.Push(&keep, evt)
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error scanning history file: %v", err)
	}

	events := []ChangeEvent(keep)
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})
	return events
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func asciiLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// containsFoldASCII reports whether haystack contains needle, ignoring ASCII
// case. It allocates nothing, which matters when scanning millions of lines.
func containsFoldASCII(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		matched := true
		for j := 0; j < len(needle); j++ {
			if asciiLower(haystack[i+j]) != asciiLower(needle[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// packageStateKey includes the architecture so multi-arch packages do not
// overwrite each other in the change history.
func packageStateKey(name, arch string) string {
	if arch == "" {
		return name
	}
	return name + " (" + arch + ")"
}

func ComputeDiffs(prev, curr map[string]map[string]string) []ChangeEvent {
	var diffs []ChangeEvent
	now := time.Now().UTC()

	for host, currPkgs := range curr {
		prevPkgs, hostExisted := prev[host]
		if !hostExisted {
			for pkg, ver := range currPkgs {
				diffs = append(diffs, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					NewVersion: ver,
					Action:     "ADDED",
				})
			}
			continue
		}

		for pkg, currVer := range currPkgs {
			prevVer, pkgExisted := prevPkgs[pkg]
			switch {
			case !pkgExisted:
				diffs = append(diffs, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					NewVersion: currVer,
					Action:     "ADDED",
				})
			case prevVer != currVer:
				diffs = append(diffs, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					OldVersion: prevVer,
					NewVersion: currVer,
					Action:     "MODIFIED",
				})
			}
		}
	}

	for host, prevPkgs := range prev {
		currPkgs, hostStillExists := curr[host]
		for pkg, prevVer := range prevPkgs {
			if !hostStillExists {
				// A host that stopped reporting no longer has any packages.
				diffs = append(diffs, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					OldVersion: prevVer,
					Action:     "REMOVED",
				})
				continue
			}
			if _, pkgStillExists := currPkgs[pkg]; !pkgStillExists {
				diffs = append(diffs, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					OldVersion: prevVer,
					Action:     "REMOVED",
				})
			}
		}
	}

	return diffs
}
