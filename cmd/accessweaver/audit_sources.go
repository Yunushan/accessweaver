package main

import "path/filepath"

// Trust/privacy checks remain in the native storage backend. These metadata
// references prevent a direct output from targeting either storage file.
func auditStorageReferences(directory string) []auditPathReference {
	return []auditPathReference{{path: filepath.Join(directory, "events.journal")}, {path: filepath.Join(directory, ".actor-key")}}
}
func auditFileReferences(required, optional []string, follow bool) []auditPathReference {
	refs := make([]auditPathReference, 0, len(required)+len(optional))
	for _, path := range required {
		refs = append(refs, auditPathReference{path: path, followLinks: follow})
	}
	for _, path := range optional {
		refs = append(refs, auditPathReference{path: path, followLinks: follow, optional: true})
	}
	return refs
}
