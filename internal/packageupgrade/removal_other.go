//go:build !darwin || (!amd64 && !arm64)

package packageupgrade

import "errors"

func InspectProductRemoval() (ProductRemovalInspection, error) {
	return ProductRemovalInspection{}, errors.New("product removal inspection requires macOS")
}
