package workflow

import (
	"errors"
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
