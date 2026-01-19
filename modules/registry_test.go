package modules

import (
	"testing"
)

// mockModule implements Module interface for testing
type mockModule struct {
	name                string
	description         string
	supportedPlacements []string
	requiresSink        string
}

func (m *mockModule) Info() ModuleInfo {
	return ModuleInfo{
		Name:                m.name,
		Description:         m.description,
		SupportedPlacements: m.supportedPlacements,
		RequiresSink:        m.requiresSink,
	}
}

func (m *mockModule) Handle(ctx *HandlerContext) (*Result, error) {
	return &Result{
		Data: "mock result",
	}, nil
}

// TestRegister tests module registration
func TestRegister(t *testing.T) {
	// Create a fresh registry for testing
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	mock := &mockModule{
		name:                "test_register_module",
		description:         "Test module for registration",
		supportedPlacements: []string{"query_param"},
		requiresSink:        "sqlite",
	}

	err := testRegistry.Register(mock)
	if err != nil {
		t.Fatalf("Failed to register module: %v", err)
	}

	if !testRegistry.Has("test_register_module") {
		t.Error("Expected module to be registered")
	}
}

// TestGet tests getting a registered module
func TestGet(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	mock := &mockModule{
		name:                "test_get_module",
		description:         "Test module for get",
		supportedPlacements: []string{"header"},
		requiresSink:        "filesystem",
	}

	testRegistry.Register(mock)

	mod, err := testRegistry.Get("test_get_module")
	if err != nil {
		t.Fatalf("Failed to get registered module: %v", err)
	}

	info := mod.Info()
	if info.Name != "test_get_module" {
		t.Errorf("Expected name 'test_get_module', got '%s'", info.Name)
	}
}

// TestGet_NotFound tests getting a non-existent module
func TestGet_NotFound(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	_, err := testRegistry.Get("nonexistent_module")
	if err == nil {
		t.Error("Expected error for non-existent module")
	}
}

// TestHas tests checking if module exists
func TestHas(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	mock := &mockModule{
		name: "test_has_module",
	}

	// Should not exist initially
	if testRegistry.Has("test_has_module") {
		t.Error("Expected module to not exist initially")
	}

	testRegistry.Register(mock)

	// Should exist after registration
	if !testRegistry.Has("test_has_module") {
		t.Error("Expected module to exist after registration")
	}
}

// TestList tests listing all registered modules
func TestList(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	// Register multiple modules
	testRegistry.Register(&mockModule{name: "module_a"})
	testRegistry.Register(&mockModule{name: "module_b"})
	testRegistry.Register(&mockModule{name: "module_c"})

	list := testRegistry.List()

	if len(list) != 3 {
		t.Errorf("Expected 3 modules, got %d", len(list))
	}

	// Check all are present
	found := make(map[string]bool)
	for _, info := range list {
		found[info.Name] = true
	}

	if !found["module_a"] || !found["module_b"] || !found["module_c"] {
		t.Error("Not all expected modules found in list")
	}
}

// TestList_Empty tests listing with no modules
func TestList_Empty(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	list := testRegistry.List()

	if len(list) != 0 {
		t.Errorf("Expected 0 modules, got %d", len(list))
	}
}

// TestRegister_Duplicate tests that re-registering returns error
func TestRegister_Duplicate(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	mock1 := &mockModule{
		name:        "duplicate_module",
		description: "First version",
	}
	mock2 := &mockModule{
		name:        "duplicate_module",
		description: "Second version",
	}

	err := testRegistry.Register(mock1)
	if err != nil {
		t.Fatalf("First registration failed: %v", err)
	}

	err = testRegistry.Register(mock2)
	if err == nil {
		t.Error("Expected error when registering duplicate module")
	}
}

// TestRegister_EmptyName tests registering module with empty name
func TestRegister_EmptyName(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	mock := &mockModule{
		name: "",
	}

	err := testRegistry.Register(mock)
	if err == nil {
		t.Error("Expected error when registering module with empty name")
	}
}

// TestModuleInfo_FromRegistry tests that Info returns correct data
func TestModuleInfo_FromRegistry(t *testing.T) {
	testRegistry := &Registry{
		modules: make(map[string]Module),
	}

	mock := &mockModule{
		name:                "info_test_module",
		description:         "Description for info test",
		supportedPlacements: []string{"query_param", "header", "cookie"},
		requiresSink:        "command",
	}

	testRegistry.Register(mock)

	mod, _ := testRegistry.Get("info_test_module")
	info := mod.Info()

	if info.Name != "info_test_module" {
		t.Errorf("Expected name 'info_test_module', got '%s'", info.Name)
	}
	if info.Description != "Description for info test" {
		t.Errorf("Expected description 'Description for info test', got '%s'", info.Description)
	}
	if len(info.SupportedPlacements) != 3 {
		t.Errorf("Expected 3 placements, got %d", len(info.SupportedPlacements))
	}
	if info.RequiresSink != "command" {
		t.Errorf("Expected RequiresSink 'command', got '%s'", info.RequiresSink)
	}
}

// TestModuleHandle tests that Handle returns result
func TestModuleHandle(t *testing.T) {
	mock := &mockModule{
		name: "handle_test",
	}

	ctx := &HandlerContext{
		Input:     "test input",
		Placement: "query_param",
		Param:     "id",
		Config:    nil,
	}

	result, err := mock.Handle(ctx)
	if err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	if result.Data != "mock result" {
		t.Errorf("Expected 'mock result', got '%v'", result.Data)
	}
}
