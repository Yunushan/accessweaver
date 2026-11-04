package packageupgrade

import (
	"bytes"
	"strings"
	"testing"
)

func TestRemovalQuarantineDestinationAndFenceBinding(t *testing.T) {
	before := removalFenceState()
	plan := removalFencePlanForStateFixture(before)
	fence, _, e := newRemovalFence(before, plan.DesktopRecordSHA256, strings.Repeat("e", 64), plan)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := removalQuarantineSeed(fence, plan, plan.Authority.RootDevice, 999)
	if e != nil {
		t.Fatal(e)
	}
	journal, _ := decodeRemovalJournal(nil, seed, 1)
	intent, _ := nextRemovalJournalLine(seed, journal)
	for _, change := range []string{"destination", "device", "empty-destination", "fence", "plan", "public-parent", "public-root"} {
		t.Run(change, func(t *testing.T) {
			f, p := fence, plan
			raw, _ := encodeRemovalPlan(plan)
			p, e = decodeRemovalPlan(raw)
			if e != nil {
				t.Fatal(e)
			}
			device, inode := p.Authority.RootDevice, uint64(999)
			switch change {
			case "destination":
				inode++
			case "device":
				device++
			case "empty-destination":
				inode = 0
			case "fence":
				f.InventorySHA256 = strings.Repeat("a", 64)
			case "plan":
				p.DesktopRecordSHA256 = strings.Repeat("a", 64)
			case "public-parent":
				for i := range p.Roots {
					if p.Roots[i].Kind == "public" {
						p.Roots[i].ParentInode++
					}
				}
			case "public-root":
				for i := range p.Roots {
					if p.Roots[i].Kind == "public" {
						p.Roots[i].Objects[0].Inode++
					}
				}
			}
			other, e := removalQuarantineSeed(f, p, device, inode)
			if e == nil {
				if other == seed {
					t.Fatal("quarantine binding unchanged")
				}
				if _, e = decodeRemovalJournal(intent, other, 1); e == nil {
					t.Fatal("foreign quarantine intent accepted")
				}
			}
		})
	}
	raw := []byte{}
	for entry := 0; entry < 2; entry++ {
		before, _ := decodeRemovalJournal(raw, seed, 1)
		next, _ := nextRemovalJournalLine(seed, before)
		for cut := 0; cut < len(next); cut++ {
			partial := append(append([]byte{}, raw...), next[:cut]...)
			got, e := decodeRemovalJournal(partial, seed, 1)
			if e != nil || got.entries != entry || got.completed != 0 || got.pending != (entry == 1) || !bytes.Equal(got.tail, next[:cut]) {
				t.Fatal(entry, cut, got, e)
			}
		}
		raw = append(raw, next...)
	}
	done, e := decodeRemovalJournal(raw, seed, 1)
	if e != nil || done.completed != 1 || done.pending {
		t.Fatal(done, e)
	}
	if _, e = decodeRemovalJournal(append(raw, 'x'), seed, 1); e == nil {
		t.Fatal("extra quarantine action accepted")
	}
}
