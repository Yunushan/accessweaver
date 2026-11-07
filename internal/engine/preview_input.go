package engine

// Preview needs kind/size observations without demanding file-data access.
// unixExecutable records Unix mode bits; it is not a Windows permission grant.
type previewInputMetadata struct {
	regular        bool
	size           int64
	unixExecutable bool
}
