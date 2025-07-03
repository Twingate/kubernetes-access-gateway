package version

var (
	// Version represents the application version, set at build time via ldflags.
	// Defaults to "dev" during development.
	Version = "dev"
)
