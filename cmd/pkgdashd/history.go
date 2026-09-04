package main

import (
	"bufio"
	"encoding/json"
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

type HistoryManager struct {
	mu       sync.RWMutex
	filePath string
}

func NewHistoryManager(dataPath string) *HistoryManager {
	return &HistoryManager{
		filePath: filepath.Join(dataPath, "history.jsonl"),
	}
}

func (hm *HistoryManager) RecordChanges(events []ChangeEvent) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

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
		_, _ = f.Write(append(data, '\n'))
	}
}

func (hm *HistoryManager) GetHistory(hostname, pkgName string, limit int) []ChangeEvent {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	f, err := os.Open(hm.filePath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	var events []ChangeEvent
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var evt ChangeEvent
		if err := json.Unmarshal([]byte(line), &evt); err == nil {
			if hostname != "" && !strings.EqualFold(evt.Hostname, hostname) {
				continue
			}
			if pkgName != "" && !strings.EqualFold(evt.Package, pkgName) {
				continue
			}
			events = append(events, evt)
		}
	}
	_ = scanner.Err()

	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	if limit > 0 && len(events) > limit {
		return events[:limit]
	}
	return events
}

func ComputeDiffs(prev, curr map[string]map[string]string) []ChangeEvent {
	var diffs []ChangeEvent
	now := time.Now().UTC()

	// Check for added or modified
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
			if !pkgExisted {
				diffs = append(diffs, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					NewVersion: currVer,
					Action:     "ADDED",
				})
			} else if prevVer != currVer {
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

	// Check for removed
	for host, prevPkgs := range prev {
		currPkgs, hostStillExists := curr[host]
		if !hostStillExists {
			continue
		}
		for pkg, prevVer := range prevPkgs {
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
