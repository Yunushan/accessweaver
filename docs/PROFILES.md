# Profiles, storage and portability

A profile is a versioned JSON object. The Go backend validates schema and field limits; launch preview additionally validates the engine, platform, executable and adapter requirements. A profile can therefore be valid and editable while still requiring setup before launch.

## Example

```json
{
  "version": 1,
  "id": "personal-proxy",
  "name": "Personal local proxy",
  "description": "An editable ByeDPI starting point.",
  "category": "Custom",
  "engine": "byedpi",
  "binary": "",
  "configPath": "",
  "sha256": "",
  "args": ["--ip", "127.0.0.1", "--port", "1080", "--split", "2"],
  "routing": {
    "includeDomains": ["example.com"],
    "excludeDomains": [],
    "applications": []
  },
  "probe": {
    "host": "example.com",
    "port": 443,
    "tls": true,
    "timeoutSeconds": 5
  },
  "notes": "Set an application's SOCKS5 proxy separately. Test the strategy locally."
}
```

`binary` may be empty to search the adapter's approved executable names on `PATH`. `configPath` is optional except for WireSock, sing-box and Xray; those adapters require an absolute local path. Profile export contains the path, not the file or its credentials. Absolute paths usually need updating when moving between machines.

## Field reference

| Field | Meaning |
|---|---|
| `version` | Must be `1` |
| `id` | 2–63 lowercase ASCII letters, digits or hyphens; first character a letter; also the stored filename |
| `name` | Nonempty display name, up to 100 bytes |
| `description`, `category`, `notes` | Editable display metadata; description up to 4,000 bytes, notes up to 10,000 bytes |
| `engine` | Engine ID from the catalog; launch preview checks that it is recognized |
| `binary` | Absolute executable path or a bare `PATH` name; OS-specific basename checked at launch |
| `configPath` | External configuration; supported only for WireSock, sing-box and Xray |
| `sha256` | Optional 64-character hex digest of the executable; checked again before launch |
| `args` | Up to 128 literal arguments, each at most 4,096 bytes; no shell interpolation |
| `routing.includeDomains`, `routing.excludeDomains` | Up to 4,096 entries each; supported mappings differ by adapter |
| `routing.applications` | Reserved; nonempty values block launch |
| `probe` | Host/IP, port 1–65,535, TLS switch and timeout 1–60 seconds |
| `updatedAt` | RFC 3339 timestamp managed by the store on save |

Unknown JSON fields and additional trailing JSON objects are rejected. Profiles are limited to 1 MiB. Length limits use Go string byte counts, so some non-ASCII characters occupy more than one byte.

In the guided editor, write **one argument per line**. For example, the two arguments `--port` and `1080` occupy separate lines. Do not paste a whole shell command, quote a path as if it were shell syntax, or include the executable name in `args`. Spaces inside one JSON argument are preserved.

## Local storage

The default root is `os.UserConfigDir()` plus `AccessWeaver`:

| OS | Usual root |
|---|---|
| Windows | `%AppData%\AccessWeaver` |
| macOS | `~/Library/Application Support/AccessWeaver` |
| Linux, FreeBSD, OpenBSD | `$XDG_CONFIG_HOME/AccessWeaver`, otherwise `~/.config/AccessWeaver` |

`profiles/ID.json` holds saved profiles. `generated/` contains generated domain files. Use `ACCESSWEAVER_HOME` to select another root. The store requests private directory/file modes where supported and replaces profile files atomically. Windows ACLs follow the user environment; profiles are not encrypted.

Starter profiles are seeded once per configuration root, preserving existing files. A seed marker prevents deleted starter profiles from reappearing on later startups. CLI `import` explicitly replaces an existing ID; export a backup or change the imported ID first if you need both copies. Dashboard import opens a new draft and renames a known collision.

Connected dashboard saves compare the `updatedAt` revision originally loaded by the editor. A stale save, duplicate creation or save of a deleted profile returns HTTP 409 without replacing saved data. Deletion requires a JSON body containing the reviewed `expectedUpdatedAt` value and also rejects stale revisions. A conflict leaves the draft available: copy or export any edits you need, close the editor, reload the dashboard and reopen the current profile before merging changes. Revision checks coordinate cooperating AccessWeaver processes on the same OS and local filesystem through `.profiles.lock`. Reads, writes, deletion and first-run seeding share this OS lock. Contention waits up to five seconds or until the request is canceled. A timed-out wait returns HTTP 503 with `Retry-After: 1`, preserving the draft for a later retry. Manual file writes, sharing one store between Windows and WSL, and network-filesystem locking are not qualified. Offline browser storage does not provide these server revision checks.

Eligible overlapping inventory reads share one worker per Store. Cancelling the last caller requests cancellation but cannot interrupt every native filesystem read or close. An abandoned worker retains its slot until that read and its cleanup attempt return; fresh callers receive a temporary busy result instead of starting additional workers. A caller arriving during healthy cleanup waits cancellably, then retries admission to a fresh transaction. One five-second cleanup-admission budget covers that caller across repeated finishing transactions; OS-lock acquisition retains its separate five-second contention budget. These are not a whole-call or native-I/O deadline. Completion is marked non-joinable while the OS lock is held, so a later caller cannot receive an old snapshot after a newer write. The control mutex is released during native cleanup, allowing callers to cancel promptly. The existing Windows impersonation path still reads on its own OS thread.

This bounds active shared inventory workers and cleanup attempts. It adds no profile-count limit, caches no completed inventory, and gives no hard native-I/O deadline or guarantee that a failed close released OS resources. Source tests gate a non-cooperative read and cleanup, verify repeated retries retain one slot, and confirm a later transaction sees a newly committed profile. The unchanged concurrent freshness test caught an earlier healthy-cleanup refusal on hosted Linux ARM; the [source-bound failure record](qualification/d02c3bcc0aa8-linux-arm64-inventory-finalization-regression.json) retains that regression separately from the [a18844b corrected-source result](qualification/a18844bd99b9-linux-arm64-inventory-cleanup-correction.json), where both complete hosted Linux ARM unit and race jobs passed with the original freshness test unchanged.

The CLI holds `.controller.lock` while `ui`, `run` or `import` uses the root. A second foreground controller or CLI import is rejected before seeding or launch. Use dashboard import while the UI is running; close the active controller before CLI import. Read-only `profiles`, `show` and `preview` remain available, using the profile lock for consistent access. Lock files remain after exit: do not delete or replace them to clear a busy message. The OS releases ownership when the handle or process exits, including forced termination. An older AccessWeaver binary that does not use these locks must not share an active store.

Offline mode uses browser local storage and cannot launch engines or run diagnostics. Browser storage can be cleared by the browser and is separate from Go profile files. Export JSON before switching devices or clearing site data. The desktop backend performs authoritative validation on import.

## Sharing safely

Profiles are configurations for executable software, not trusted documents. Review native arguments, Lua scripts and external configuration paths before running someone else's profile. Keep VPN keys, passwords and tokens in protected engine configuration files. Exporting a path does not encrypt it or transfer its referenced file.

See [engine rules](ENGINES.md) for how exclusions are compiled and why a process launch or direct diagnostic is not an end-to-end routing test.
