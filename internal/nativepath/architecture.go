package nativepath

import "errors"

func windowsMachineArchitecture(native uint16) (string, error) {
	switch native {
	case 0x8664: // IMAGE_FILE_MACHINE_AMD64
		return "amd64", nil
	case 0xaa64: // IMAGE_FILE_MACHINE_ARM64
		return "arm64", nil
	default:
		return "", errors.New("unsupported native Windows architecture")
	}
}
