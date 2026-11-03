package packageupgrade

import (
	"strings"
	"testing"
)

func TestProductBindingRequiresSealedMatchingCleanApplication(t *testing.T) {
	desktop := desktopFixture().Build
	core := deploymentIdentity{desktop.Version, strings.Repeat("a", 64), strings.Repeat("b", 64)}
	if e := validateProductBinding(core, desktop, "application"); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"metadata", "version", "manifest", "payload", "dirty", "source", "platform", "arch"} {
		t.Run(kind, func(t *testing.T) {
			c, b, role := core, desktop, "application"
			switch kind {
			case "metadata":
				role = "metadata"
			case "version":
				c.Version = "0.1.1-alpha"
			case "manifest":
				c.ManifestSHA256 = ""
			case "payload":
				c.PayloadSHA256 = strings.Repeat("z", 64)
			case "dirty":
				b.SourceState = "dirty"
			case "source":
				b.Commit = "unknown"
			case "platform":
				b.Platform = "linux"
			case "arch":
				b.Arch = "386"
			}
			if e := validateProductBinding(c, b, role); e == nil {
				t.Fatal("unbound product identity accepted")
			}
		})
	}
}

func TestProductHelperHasNoEnvironmentSealOverride(t *testing.T) {
	t.Setenv("ACCESSWEAVER_DEPLOYMENT_MANIFEST_SHA256", strings.Repeat("a", 64))
	t.Setenv("ACCESSWEAVER_DEPLOYMENT_PAYLOAD_SHA256", strings.Repeat("b", 64))
	t.Setenv("ACCESSWEAVER_DESKTOP_RECORD_SHA256", strings.Repeat("c", 64))
	t.Setenv("ACCESSWEAVER_PRODUCT_COMPONENT", "application")
	if _, e := compiledProductIdentity(); e == nil {
		t.Fatal("unsealed product helper accepted")
	}
}
