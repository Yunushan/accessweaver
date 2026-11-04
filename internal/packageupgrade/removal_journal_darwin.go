//go:build darwin && (amd64 || arm64)

package packageupgrade

import (
	"bytes"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/Yunushan/accessweaver/internal/darwintrust"
	"golang.org/x/sys/unix"
)

func readRemovalJournalAt(dir *os.File, owner uint32, seed string, actions int) ([]byte, syscall.Stat_t, removalJournal, error) {
	var st syscall.Stat_t
	var named unix.Stat_t
	if e := unix.Fstatat(int(dir.Fd()), removalJournalName, &named, unix.AT_SYMLINK_NOFOLLOW); errors.Is(e, unix.ENOENT) {
		journal, e := decodeRemovalJournal(nil, seed, actions)
		return nil, st, journal, e
	} else if e != nil {
		return nil, st, removalJournal{}, e
	}
	if owner != 0 {
		return nil, st, removalJournal{}, errors.New("removal progress requires root authority")
	}
	raw, st, e := readAt(dir, removalJournalName, maxRemovalJournalBytes)
	if e != nil {
		return nil, st, removalJournal{}, e
	}
	if st.Mode&07777 != 0600 {
		return nil, st, removalJournal{}, errors.New("removal journal mode differs")
	}
	if e = removalFileStillAt(dir, removalJournalName, st); e != nil {
		return nil, st, removalJournal{}, e
	}
	journal, e := decodeRemovalJournal(raw, seed, actions)
	return raw, st, journal, e
}

// Persist/repair only an exact recognized chain. A partial suffix cannot grant
// an action. Sync succeeds before any payload unlink is attempted. Even an
// existing complete pending record is re-synced on restart.
func (r *removalIntentStore) persistRemovalJournal(expected []byte, appendRecord bool) ([]byte, removalJournal, error) {
	return r.persistRemovalJournalMode(expected, appendRecord, false)
}

// A complete readable record may have survived a failed sync. Acknowledgment
// must sync it again without appending or trimming a later partial record.
func (r *removalIntentStore) syncObservedRemovalJournal(expected []byte) error {
	_, _, e := r.persistRemovalJournalMode(expected, false, true)
	return e
}
func (r *removalIntentStore) persistRemovalJournalMode(expected []byte, appendRecord, preserveTail bool) (raw []byte, journal removalJournal, result error) {
	if preserveTail && appendRecord {
		return nil, journal, errors.New("invalid removal journal persistence mode")
	}
	if e := r.verifyIntentMetadata(); e != nil {
		return nil, journal, e
	}
	actions, e := removalAllActions(r.plan)
	if e != nil {
		return nil, journal, e
	}
	seed := removalJournalSeed(r.fence)
	actual, st, journal, e := readRemovalJournalAt(r.store.current, 0, seed, len(actions))
	if e != nil || !bytes.Equal(actual, expected) {
		return nil, removalJournal{}, errors.Join(e, errors.New("removal journal changed before persistence"))
	}
	var file *os.File
	created := st.Ino == 0
	if preserveTail && created {
		return nil, removalJournal{}, errors.New("cannot acknowledge absent removal progress")
	}
	if created {
		file, e = darwintrust.CreateRegularAt(r.store.current, removalJournalName, 0)
		if e == nil {
			e = file.Chown(0, 0)
		}
	} else {
		var fd int
		fd, e = unix.Openat(int(r.store.current.Fd()), removalJournalName, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if e == nil {
			file = os.NewFile(uintptr(fd), "protected-removal-journal")
			e = deploymentObject(file, false, 0, 0600)
			if e == nil {
				var info os.FileInfo
				info, e = file.Stat()
				if e == nil && !sameState(st, *info.Sys().(*syscall.Stat_t)) {
					e = errors.New("removal journal vnode changed before append")
				}
			}
		}
	}
	if file != nil {
		defer func() { result = errors.Join(result, file.Close()) }()
	}
	if e != nil {
		return nil, removalJournal{}, e
	}
	raw = append([]byte{}, actual[:journal.validBytes]...)
	// Truncate only a verified exact prefix of the next canonical record.
	if preserveTail {
		raw = append([]byte{}, actual...)
	}
	if len(journal.tail) > 0 && !preserveTail {
		if e = file.Truncate(int64(journal.validBytes)); e != nil {
			return nil, removalJournal{}, e
		}
	}
	if appendRecord {
		if journal.entries >= 2*len(actions) {
			return nil, removalJournal{}, errors.New("removal journal already complete")
		}
		line, e := nextRemovalJournalLine(seed, journal)
		if e != nil {
			return nil, removalJournal{}, e
		}
		n, e := file.WriteAt(line, int64(journal.validBytes))
		if e != nil || n != len(line) {
			return nil, removalJournal{}, errors.Join(e, io.ErrShortWrite)
		}
		raw = append(raw, line...)
	}
	if e = r.store.phase("removal-journal-before-file-sync"); e != nil {
		return nil, removalJournal{}, e
	}
	if e = fullDeploymentSync(file); e != nil {
		return nil, removalJournal{}, e
	}
	// A prior attempt may have created this name but failed its directory sync.
	// Re-sync the containing state directory on every retry before unlinking.
	if e = r.store.phase("removal-journal-before-directory-sync"); e != nil {
		return nil, removalJournal{}, e
	}
	if e = fullDeploymentSync(r.store.current); e != nil {
		return nil, removalJournal{}, e
	}
	// Recheck both the held file and its named identity after the durable write.
	info, e := file.Stat()
	if e != nil {
		return nil, removalJournal{}, e
	}
	if e = removalFileStillAt(r.store.current, removalJournalName, *info.Sys().(*syscall.Stat_t)); e != nil {
		return nil, removalJournal{}, e
	}
	checked, _, decoded, e := readRemovalJournalAt(r.store.current, 0, seed, len(actions))
	if e != nil || !bytes.Equal(checked, raw) {
		return nil, removalJournal{}, errors.Join(e, errors.New("persisted removal journal differs"))
	}
	return raw, decoded, nil
}
