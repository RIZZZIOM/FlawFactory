package sinks

// Sink is a marker interface for all sink types
type Sink interface {
	// Close releases any resources held by the sink
	Close() error
}

// SinkType identifies the type of sink
type SinkType string

const (
	SinkTypeSQLite     SinkType = "sqlite"
	SinkTypeFilesystem SinkType = "filesystem"
	SinkTypeCommand    SinkType = "command"
	SinkTypeHTTP       SinkType = "http"
)
