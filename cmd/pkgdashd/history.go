package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
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
	events   []ChangeEvent
}

func NewHistoryManager(dataPath string) *HistoryManager {
	hm := &HistoryManager{
		filePath: filepath.Join(dataPath, "history.jsonl"),
		events:   make([]ChangeEvent, 0),
	}
	hm.loadEvents()
	return hm
}

func (hm *HistoryManager) loadEvents() {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	f, err := os.Open(hm.filePath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var evt ChangeEvent
		if err := json.Unmarshal(scanner.Bytes(), &evt); err == nil {
			hm.events = append(hm.events, evt)
		}
	}
}

func (hm *HistoryManager) RecordChanges(events []ChangeEvent) {
	if len(events) == 0 {
		return
	}

	hm.mu.Lock()
	defer hm.mu.Unlock()

	f, err := os.OpenFile(hm.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, evt := range events {
		hm.events = append(hm.events, evt)
		if data, err := json.Marshal(evt); err == nil {
			_, _ = writer.Write(data)
			_, _ = writer.WriteString("\n")
		}
	}
	_ = writer.Flush()
}

func (hm *HistoryManager) GetHistory(hostname, pkgName string, limit int) []ChangeEvent {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	result := make([]ChangeEvent, 0)
	for i := len(hm.events) - 1; i >= 0; i-- {
		evt := hm.events[i]
		if hostname != "" && !strings.EqualFold(evt.Hostname, hostname) {
			continue
		}
		if pkgName != "" && !strings.EqualFold(evt.Package, pkgName) {
			continue
		}
		result = append(result, evt)
		if limit > 0 && len(result) >= limit {
			break
		}
	}
	return result
}

func ComputeDiffs(oldState, newState map[string]map[string]string) []ChangeEvent {
	var events []ChangeEvent
	now := time.Now().UTC()

	if len(oldState) == 0 {
		return events
	}

	for host, newPkgs := range newState {
		oldPkgs, hostExisted := oldState[host]
		if !hostExisted {
			for pkg, ver := range newPkgs {
				events = append(events, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					NewVersion: ver,
					Action:     "ADDED",
				})
			}
			continue
		}

		for pkg, newVer := range newPkgs {
			oldVer, pkgExisted := oldPkgs[pkg]
			if !pkgExisted {
				events = append(events, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					NewVersion: newVer,
					Action:     "ADDED",
				})
			} else if oldVer != newVer {
				events = append(events, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					OldVersion: oldVer,
					NewVersion: newVer,
					Action:     "MODIFIED",
				})
			}
		}

		for pkg, oldVer := range oldPkgs {
			if _, exists := newPkgs[pkg]; !exists {
				events = append(events, ChangeEvent{
					Timestamp:  now,
					Hostname:   host,
					Package:    pkg,
					OldVersion: oldVer,
					Action:     "REMOVED",
				})
			}
		}
	}

	return events
}
