# Audit command output failures

Explicit Linux audit producers need to handle failed standard streams before returning their recording result. [Go's SIGPIPE behavior](https://pkg.go.dev/os/signal#hdr-SIGPIPE) otherwise permits the process to terminate when stdout or stderr has no reader, before Write returns an error. The pinned Go 1.27.3 source and actual unprivileged subprocess tests reproduced this for both descriptors.

Initialize, import, the audited profile desktop, explicit policy transactions and export-recorded now register for SIGPIPE during their command scope. Broken writes return EPIPE to the existing output/error contracts. The scope stops its own registration on return, preserving other subscribers and restoring prior handling; it does not permanently ignore the signal. Output errors do not grant a profile capability, policy permission, retry or trusted new checkpoint.

| Failure point | Result to preserve |
| --- | --- |
| Initialization checkpoint | The initialized private key and genesis remain. The command returns its fixed output-unavailable error; recover/authenticate genesis independently. |
| Intent checkpoint | No covered import, policy transaction or event export dispatches. A local refused outcome is attempted if storage remains available. |
| Event export write | A failed or short write is indeterminate, including an error reported with zero bytes; available observation output can still report the intent and result. |
| Outcome checkpoint after an operation | The caller receives uncertainty even when a durable local completed/refused outcome exists. Preserve the original observation and reconcile incomplete output independently. |
| Audited desktop startup information | Startup returns its fixed output error and releases controller ownership before returning; no profile mutation is dispatched by that failed startup. |

A complete write is a local writer result. It proves no reader delivery, destination fsync or collector acknowledgment. A failed output stream may contain no complete checkpoint or only a prefix. Local intent/refusal records can make an externally retained old head stale even though the covered operation never ran. Preserve the original endpoints and journal; never adopt an unknown tail, overwrite a trusted checkpoint with partial output, or reset the stream automatically.

Source subprocess tests create actual closed FD 1 and FD 2 pipes under an ordinary Linux UID. They verify indeterminate event output, refused unobserved export/import/policy intent, no imported profile root, preserved initialization, clean desktop startup failure, controller lock release and restoration of default SIGPIPE behavior after the command scope. Synthetic writer tests separately cover short writes, cancellation, panic and outcome append/observation failure. These are source and local protected-storage checks, not installed-product, reboot/power-loss or all-platform qualification.

See [the audit contract](AUDIT_EVENTS.md) and [recorded export](RECORDED_AUDIT_EXPORT.md) for snapshot boundaries, private observation destinations, consent and remaining enterprise work.
