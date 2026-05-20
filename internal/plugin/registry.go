// Package plugin contains the plugin registry.
package plugin

import (
	"fmt"
	"sync"
)

var (
	mu       sync.RWMutex
	registry = map[string]ScanPlugin{}
)

// Register registers a plugin with the global registry.
// Called from each plugin package's init() function.
func Register(p ScanPlugin) {
	mu.Lock()
	defer mu.Unlock()
	registry[p.Name()] = p
}

// Get returns a plugin by name.
func Get(name string) (ScanPlugin, error) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	return p, nil
}

// All returns all registered plugins.
func All() []ScanPlugin {
	mu.RLock()
	defer mu.RUnlock()
	plugins := make([]ScanPlugin, 0, len(registry))
	for _, p := range registry {
		plugins = append(plugins, p)
	}
	return plugins
}

// Active returns plugins whose names appear in the active list.
// If active is empty, returns all registered plugins.
func Active(active []string) []ScanPlugin {
	if len(active) == 0 {
		return All()
	}
	mu.RLock()
	defer mu.RUnlock()
	var plugins []ScanPlugin
	for _, name := range active {
		if p, ok := registry[name]; ok {
			plugins = append(plugins, p)
		}
	}
	return plugins
}
