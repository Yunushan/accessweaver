//go:build windows

package audit

import (
	"encoding/binary"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsAuditTestOwner   = "S-1-5-21-100001-100002-100003-100004"
	windowsAuditTestForeign = "S-1-5-21-200001-200002-200003-200004"
)

func windowsAuditTestDescriptor(t *testing.T, sddl string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("native test descriptor conversion failed: %v", err)
	}
	return sd
}

func TestWindowsAuditPrivateDescriptors(t *testing.T) {
	ownerGrant := "(A;;FA;;;" + windowsAuditTestOwner + ")"
	for _, tc := range []struct {
		name, sddl string
		accept     bool
	}{
		{"owner", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant, true},
		{"owner and system", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;;FA;;;SY)", true},
		{"directory propagation", "O:" + windowsAuditTestOwner + "D:P(A;OICI;FA;;;" + windowsAuditTestOwner + ")(A;OICI;FA;;;SY)", true},
		{"owner rights resolves validated owner", "O:" + windowsAuditTestOwner + "D:P(A;;FA;;;OW)", true},
		{"generic full control", "O:" + windowsAuditTestOwner + "D:P(A;;GA;;;" + windowsAuditTestOwner + ")", true},
		{"split complete owner grant", "O:" + windowsAuditTestOwner + "D:P(A;;0x001e0000;;;" + windowsAuditTestOwner + ")(A;;0x000101ff;;;" + windowsAuditTestOwner + ")", true},
		{"foreign read", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;;FR;;;" + windowsAuditTestForeign + ")", false},
		{"everyone read", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;;FR;;;WD)", false},
		{"everyone full control", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;;FA;;;WD)", false},
		{"administrators not private", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;;FA;;;BA)", false},
		{"foreign effective propagating grant", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;OICI;FR;;;WD)", false},
		{"foreign inherit only grant", "O:" + windowsAuditTestOwner + "D:P" + ownerGrant + "(A;OICIIO;FR;;;WD)", false},
		{"unprotected", "O:" + windowsAuditTestOwner + "D:" + ownerGrant, false},
		{"inherited owner grant", "O:" + windowsAuditTestOwner + "D:P(A;ID;FA;;;" + windowsAuditTestOwner + ")", false},
		{"inherit only owner grant", "O:" + windowsAuditTestOwner + "D:P(A;OICIIO;FA;;;" + windowsAuditTestOwner + ")", false},
		{"no propagate owner grant", "O:" + windowsAuditTestOwner + "D:P(A;OICINP;FA;;;" + windowsAuditTestOwner + ")", false},
		{"empty DACL", "O:" + windowsAuditTestOwner + "D:P", false},
		{"missing DACL", "O:" + windowsAuditTestOwner, false},
		{"missing owner", "D:P" + ownerGrant, false},
		{"owner read only", "O:" + windowsAuditTestOwner + "D:P(A;;FR;;;" + windowsAuditTestOwner + ")", false},
		{"owner read write omits metadata control", "O:" + windowsAuditTestOwner + "D:P(A;;FRFW;;;" + windowsAuditTestOwner + ")", false},
		{"system grant cannot replace owner grant", "O:" + windowsAuditTestOwner + "D:P(A;;FA;;;SY)", false},
		{"owner denied", "O:" + windowsAuditTestOwner + "D:P(D;;FW;;;" + windowsAuditTestOwner + ")" + ownerGrant, false},
		{"group deny may affect owner", "O:" + windowsAuditTestOwner + "D:P(D;;FW;;;WD)" + ownerGrant, false},
		{"foreign owner", "O:" + windowsAuditTestForeign + "D:P" + ownerGrant, false},
		{"privileged owner is still mismatched", "O:SYD:P" + ownerGrant, false},
		{"owner rights is not owner identity", "O:OWD:P(A;;FA;;;OW)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd := windowsAuditTestDescriptor(t, tc.sddl)
			err := checkWindowsAuditDescriptor(sd, windowsAuditTestOwner, true)
			if tc.accept {
				if err != nil {
					t.Fatalf("private descriptor refused: %v", err)
				}
			} else if err != ErrJournalStorage {
				t.Fatalf("wanted fixed storage refusal, got %v", err)
			}
		})
	}
}

func TestWindowsAuditNullDACL(t *testing.T) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := windows.StringToSid(windowsAuditTestOwner)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.SetOwner(sid, false); err != nil {
		t.Fatal(err)
	}
	if err := sd.SetDACL(nil, true, false); err != nil {
		t.Fatal(err)
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		t.Fatal(err)
	}
	relative, err := sd.ToSelfRelative()
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []bool{false, true} {
		if err := checkWindowsAuditDescriptor(relative, windowsAuditTestOwner, private); err != ErrJournalStorage {
			t.Fatalf("null DACL accepted (private=%v): %v", private, err)
		}
	}
	runtime.KeepAlive(sid)
}

func TestWindowsAuditAncestorDescriptors(t *testing.T) {
	for _, tc := range []struct {
		name, actualOwner, aces string
		accept                  bool
	}{
		{"executing owner", windowsAuditTestOwner, "(A;;FA;;;" + windowsAuditTestOwner + ")", true},
		{"system owner with ordinary reads", "SY", "(A;;FRFX;;;WD)", true},
		{"administrator owner with ordinary reads", "BA", "(A;;FR;;;WD)", true},
		{"trusted installer owner", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", "(A;;FR;;;WD)", true},
		{"foreign create unrelated directory", "SY", "(A;;0x4;;;WD)", true},
		{"owner rights on executing owner", windowsAuditTestOwner, "(A;;FA;;;OW)", true},
		{"owner rights on system owner", "SY", "(A;;FA;;;OW)", true},
		{"trusted administrator grant", windowsAuditTestOwner, "(A;;FA;;;BA)", true},
		{"inherited read grant", "SY", "(A;OICIID;FRFX;;;WD)", true},
		{"validated inherit only grant", "SY", "(A;OICIIO;FA;;;WD)", true},
		{"creator owner inherit only", "SY", "(A;OICIIO;FA;;;CO)", true},
		{"ordinary deny grants no mutation", "SY", "(D;;FA;;;WD)(A;;FA;;;SY)", true},
		{"foreign owner", windowsAuditTestForeign, "(A;;FR;;;WD)", false},
		{"owner rights cannot validate foreign owner", windowsAuditTestForeign, "(A;;FA;;;OW)", false},
		{"owner rights cannot be owner", "OW", "(A;;FA;;;OW)", false},
		{"foreign write", "SY", "(A;;FW;;;WD)", false},
		{"foreign effective propagating full control", "SY", "(A;OICI;FA;;;WD)", false},
		{"foreign inherited full control", "SY", "(A;OICIID;FA;;;WD)", false},
		{"effective creator owner is not silently skipped", "SY", "(A;OICI;FA;;;CO)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd := windowsAuditTestDescriptor(t, "O:"+tc.actualOwner+"D:"+tc.aces)
			err := checkWindowsAuditDescriptor(sd, windowsAuditTestOwner, false)
			if tc.accept {
				if err != nil {
					t.Fatalf("safe ancestor descriptor refused: %v", err)
				}
			} else if err != ErrJournalStorage {
				t.Fatalf("wanted fixed storage refusal, got %v", err)
			}
		})
	}
	for _, rights := range []string{"0x2", "0x10", "0x40", "0x100", "SD", "WD", "WO", "GW", "GA"} {
		t.Run("foreign mutation "+rights, func(t *testing.T) {
			sd := windowsAuditTestDescriptor(t, "O:SYD:(A;;"+rights+";;;"+windowsAuditTestForeign+")")
			if err := checkWindowsAuditDescriptor(sd, windowsAuditTestOwner, false); err != ErrJournalStorage {
				t.Fatalf("ancestor mutation right %s accepted: %v", rights, err)
			}
		})
	}
}

func TestWindowsAuditCreationDescriptor(t *testing.T) {
	for _, directory := range []bool{false, true} {
		sd, err := windowsAuditSecurityDescriptor(windowsAuditTestOwner, directory)
		if err != nil {
			t.Fatal(err)
		}
		owner, _, err := sd.Owner()
		if err != nil || owner == nil || owner.String() != windowsAuditTestOwner {
			t.Fatalf("creation owner differs: %v", err)
		}
		control, _, err := sd.Control()
		if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
			t.Fatalf("creation DACL is not protected: %v", err)
		}
		acl, _, err := sd.DACL()
		if err != nil || acl == nil || acl.AceCount != 2 {
			t.Fatalf("creation DACL does not contain exactly two grants: %v", err)
		}
		for i, wantSID := range []string{windowsAuditTestOwner, windowsAuditSystemSID} {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
				t.Fatal(err)
			}
			wantFlags := uint8(0)
			if directory {
				wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
			}
			principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != wantFlags || uint32(ace.Mask) != windowsAuditFullControl || principal != wantSID {
				t.Fatalf("creation ACE %d has unexpected principal, rights, or inheritance", i)
			}
		}
		runtime.KeepAlive(sd)
	}
	for _, owner := range []string{"", "invalid", "BA", "S-1-3-0", windowsAuditOwnerRightsSID, windowsAuditTestOwner + "D:(A;;FA;;;WD)"} {
		if sd, err := windowsAuditSecurityDescriptor(owner, false); sd != nil || err != ErrJournalStorage {
			t.Fatalf("invalid creation identity was accepted: %v", err)
		}
	}
	if err := checkWindowsAuditDescriptor(nil, windowsAuditTestOwner, true); err != ErrJournalStorage {
		t.Fatalf("nil descriptor accepted: %v", err)
	}
	if err := checkWindowsAuditSecurity(windows.InvalidHandle, windowsAuditTestOwner, true); err != ErrJournalStorage {
		t.Fatalf("invalid handle did not return fixed storage refusal: %v", err)
	}
}

func TestWindowsAuditMalformedDescriptorBounds(t *testing.T) {
	sd := windowsAuditTestDescriptor(t, "O:"+windowsAuditTestOwner+"D:P(A;;FA;;;"+windowsAuditTestOwner+")(A;;FA;;;SY)")
	source := unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length()))
	base := append([]byte(nil), source...)
	runtime.KeepAlive(sd)
	aclAt := int(binary.LittleEndian.Uint32(base[16:20]))
	ownerAt := int(binary.LittleEndian.Uint32(base[4:8]))
	aceAt := aclAt + 8
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"short descriptor", func(b []byte) []byte { return b[:19] }},
		{"absolute descriptor", func(b []byte) []byte { b[3] &^= 0x80; return b }},
		{"owner out of bounds", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[4:8], uint32(len(b)+4)); return b }},
		{"owner SID length out of bounds", func(b []byte) []byte { b[ownerAt+1] = 15; return b[:ownerAt+12] }},
		{"owner SID invalid revision", func(b []byte) []byte { b[ownerAt] = 2; return b }},
		{"DACL out of bounds", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], uint32(len(b)-4)); return b }},
		{"short ACL", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[aclAt+2:aclAt+4], 4); return b }},
		{"oversized ACL", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[aclAt+2:aclAt+4], 0xfffc); return b }},
		{"impossible ACE count", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[aclAt+4:aclAt+6], 0xffff); return b }},
		{"short ACE", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[aceAt+2:aceAt+4], 8); return b }},
		{"unaligned ACE", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[aceAt+2:aceAt+4], 17); return b }},
		{"oversized ACE", func(b []byte) []byte { binary.LittleEndian.PutUint16(b[aceAt+2:aceAt+4], 0xfffc); return b }},
		{"SID extends beyond ACE", func(b []byte) []byte { b[aceAt+9] = 15; return b }},
		{"unknown ACE flags", func(b []byte) []byte { b[aceAt+1] = 0x20; return b }},
		{"inherit only without propagation", func(b []byte) []byte { b[aceAt+1] = windows.INHERIT_ONLY_ACE; return b }},
		{"no propagate without propagation", func(b []byte) []byte { b[aceAt+1] = windows.NO_PROPAGATE_INHERIT_ACE; return b }},
		{"object ACE is unsupported", func(b []byte) []byte { b[aceAt] = 5; return b }},
		{"callback ACE is unsupported", func(b []byte) []byte { b[aceAt] = 9; return b }},
		{"unsupported inherited only ACE is not skipped", func(b []byte) []byte {
			b[aceAt] = 9
			b[aceAt+1] = windows.OBJECT_INHERIT_ACE | windows.INHERIT_ONLY_ACE
			return b
		}},
		{"unsupported deny ACE is not skipped", func(b []byte) []byte { b[aceAt] = 6; return b }},
		{"unknown access mask", func(b []byte) []byte { binary.LittleEndian.PutUint32(b[aceAt+4:aceAt+8], 0x04000000); return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tc.mutate(append([]byte(nil), base...))
			for _, private := range []bool{false, true} {
				if err := checkWindowsAuditDescriptorBytes(data, windowsAuditTestOwner, private); err != ErrJournalStorage {
					t.Fatalf("malformed descriptor accepted (private=%v): %v", private, err)
				}
			}
		})
	}
}
