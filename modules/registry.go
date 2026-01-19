package modules

import (
	"fmt"
	"sync"
)

// Registry holds all registered vulnerability modules
type Registry struct {
	mu      sync.RWMutex
	modules map[string]Module
}

// Global registry instance
var globalRegistry = &Registry{
	modules: make(map[string]Module),
}

// Register adds a module to the global registry
func Register(module Module) error {
	return globalRegistry.Register(module)
}

// Get retrieves a module from the global registry
func Get(name string) (Module, error) {
	return globalRegistry.Get(name)
}

// List returns all registered module names
func List() []ModuleInfo {
	return globalRegistry.List()
}

// Register adds a module to the registry
func (r *Registry) Register(module Module) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	info := module.Info()
	if info.Name == "" {
		return fmt.Errorf("module name cannot be empty")
	}

	if _, exists := r.modules[info.Name]; exists {
		return fmt.Errorf("module '%s' is already registered", info.Name)
	}

	r.modules[info.Name] = module
	return nil
}

// Get retrieves a module by name
func (r *Registry) Get(name string) (Module, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	module, exists := r.modules[name]
	if !exists {
		return nil, fmt.Errorf("module '%s' not found", name)
	}

	return module, nil
}

// List returns info about all registered modules
func (r *Registry) List() []ModuleInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	infos := make([]ModuleInfo, 0, len(r.modules))
	for _, module := range r.modules {
		infos = append(infos, module.Info())
	}
	return infos
}

// Has checks if a module is registered
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.modules[name]
	return exists
}

// Has checks if a module is registered in the global registry
func Has(name string) bool {
	return globalRegistry.Has(name)
}

// SupportedPlacements returns the supported placements for a module
func SupportedPlacements(name string) ([]string, error) {
	module, err := Get(name)
	if err != nil {
		return nil, err
	}
	return module.Info().SupportedPlacements, nil
}

// ValidatePlacement checks if a placement is valid for a module
func ValidatePlacement(moduleName, placement string) error {
	placements, err := SupportedPlacements(moduleName)
	if err != nil {
		return err
	}

	for _, p := range placements {
		if p == placement {
			return nil
		}
	}

	return fmt.Errorf("placement '%s' is not supported by module '%s'", placement, moduleName)
}

// ValidateConfigValue checks if a config value is valid for a module
// Returns: (isValid bool, validOptions []string, defaultValue string)
// If the module doesn't define valid options for the key, returns (true, nil, "")
func ValidateConfigValue(moduleName, configKey, configValue string) (bool, []string, string) {
	module, err := Get(moduleName)
	if err != nil {
		return true, nil, "" // Module not found, can't validate
	}

	info := module.Info()
	if info.ValidVariants == nil {
		return true, nil, "" // No variants defined
	}

	validOptions, exists := info.ValidVariants[configKey]
	if !exists {
		return true, nil, "" // This config key doesn't have restrictions
	}

	// Check if value is in valid options
	for _, opt := range validOptions {
		if opt == configValue {
			return true, validOptions, ""
		}
	}

	// Invalid value - return first option as default
	defaultVal := ""
	if len(validOptions) > 0 {
		defaultVal = validOptions[0]
	}
	return false, validOptions, defaultVal
}
