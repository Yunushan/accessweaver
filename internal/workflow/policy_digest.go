package workflow

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Yunushan/accessweaver/internal/managed"
)

// PolicyDigest binds every validated workflow request field. No profile/job
// authority is granted by possessing this digest; a protected policy must approve it.
func (r Request) PolicyDigest() (string, error) {
	found := false
	for _, operation := range Catalog() {
		if operation.ID == r.Action {
			found = true
			break
		}
	}
	if !found {
		return "", errors.New("unknown workflow action")
	}
	if err := r.Validate(); err != nil {
		return "", err
	}
	return managed.InputDigest("workflow", r)
}

func workflowPermission(guard *managed.Guard, r Request) (managed.WorkflowPermission, error) {
	digest, err := r.PolicyDigest()
	if err != nil {
		return managed.WorkflowPermission{}, err
	}
	permission, err := guard.Workflow(r.Action, digest, []managed.InputPath{{Path: r.ConfigPath}, {Path: r.BundlePath, Directory: true}})
	if err == nil && permission.Managed && !permission.AllowDownloads && (r.Action == "download" || r.Action == "updates") {
		return managed.WorkflowPermission{}, fmt.Errorf("%w: remote downloads and release checks are disabled", managed.ErrDenied)
	}
	if err == nil && permission.Managed && (len(r.Args) > 0 || r.Action == "auto-install") {
		// Auto-install derives native arguments from a scan after request approval.
		// They need the same protected asset validation as caller-provided args.
		return managed.WorkflowPermission{}, fmt.Errorf("%w: managed native-argument asset validation is not implemented", managed.ErrDenied)
	}
	// A reviewed standalone download request already signs its URL and hash.
	// Implicit dependency downloads need their own administrator manifest pins.
	if err == nil && permission.Managed && r.Action == "download" {
		found := false
		for _, download := range permission.Downloads {
			if download.URL == r.DownloadURL {
				found = true
				if download.SHA256 != strings.ToLower(r.SHA256) {
					return managed.WorkflowPermission{}, fmt.Errorf("%w: request conflicts with pinned download", managed.ErrDenied)
				}
			}
		}
		if !found {
			permission.Downloads = append(permission.Downloads, managed.DownloadRule{URL: r.DownloadURL, SHA256: strings.ToLower(r.SHA256)})
		}
	}
	return permission, err
}
