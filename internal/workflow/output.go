package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// These private-data exports retain complete result values without indentation,
// HTML escaping or Unicode-separator expansion. Do not embed them in HTML/JS.
// Callers enforce result/history read limits; writer failures may leave partial
// output and must be returned to the operator.
type jobOutput struct {
	job                   Job
	startedAt, finishedAt []byte
}

func prepareJobOutput(job Job, nesting int) (jobOutput, error) {
	// Time's JSON marshaler can reject a year or zone offset. Validate both before
	// any output, retaining the existing time representation, including zero time.
	startedAt, err := json.Marshal(job.StartedAt)
	if err != nil {
		return jobOutput{}, err
	}
	finishedAt, err := json.Marshal(job.FinishedAt)
	if err != nil {
		return jobOutput{}, err
	}
	result := job.Result
	if len(result) > 0 && nesting > 0 {
		wrapped := make([]byte, 0, len(result)+2*nesting)
		for i := 0; i < nesting; i++ {
			wrapped = append(wrapped, '[')
		}
		wrapped = append(wrapped, result...)
		for i := 0; i < nesting; i++ {
			wrapped = append(wrapped, ']')
		}
		if !json.Valid(result) || !json.Valid(wrapped) {
			return jobOutput{}, errors.New("workflow result cannot be encoded at the output's JSON nesting depth")
		}
	}
	// Keep references to the immutable input, not encoded copies of every legacy
	// error/identifier in a history export. The caller owns the input lifetime.
	return jobOutput{job: job, startedAt: startedAt, finishedAt: finishedAt}, nil
}

func writeOutput(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

// Reuse one bounded scratch buffer for all metadata strings in an export. No
// whole escaped string or aggregate encoded history metadata is retained.
type jobJSONWriter struct {
	out     io.Writer
	scratch []byte
}

// writeString follows JSON string escaping (RFC 8259 section 7), with Go v1's
// replacement of each invalid UTF-8 byte. HTML/JS-only escaping is unnecessary
// for these private JSON files/responses; they must never be embedded in HTML.
func (out *jobJSONWriter) writeString(value string) error {
	// Small status replies need only a small buffer. Grow on demand and reuse it
	// across fields/records, with at most 32 KiB live scratch for large metadata.
	desired := 32 << 10
	if len(value) < desired-2 {
		desired = max(64, len(value)+2)
	}
	if len(out.scratch) < desired {
		out.scratch = make([]byte, desired)
	}
	data := append(out.scratch[:0], '"')
	for len(value) > 0 {
		// The next encoded character occupies at most six bytes.
		if len(data) > len(out.scratch)-6 {
			if err := writeOutput(out.out, data); err != nil {
				return err
			}
			data = out.scratch[:0]
		}
		c := value[0]
		switch {
		case c == '"' || c == '\\':
			data = append(data, '\\', c)
			value = value[1:]
		case c < 0x20:
			switch c {
			case '\b':
				data = append(data, '\\', 'b')
			case '\f':
				data = append(data, '\\', 'f')
			case '\n':
				data = append(data, '\\', 'n')
			case '\r':
				data = append(data, '\\', 'r')
			case '\t':
				data = append(data, '\\', 't')
			default:
				const hex = "0123456789abcdef"
				data = append(data, '\\', 'u', '0', '0', hex[c>>4], hex[c&15])
			}
			value = value[1:]
		case c < utf8.RuneSelf:
			data = append(data, c)
			value = value[1:]
		default:
			r, size := utf8.DecodeRuneInString(value)
			if r == utf8.RuneError && size == 1 {
				data = utf8.AppendRune(data, utf8.RuneError)
			} else {
				data = append(data, value[:size]...)
			}
			value = value[size:]
		}
	}
	if len(data) == len(out.scratch) {
		if err := writeOutput(out.out, data); err != nil {
			return err
		}
		data = out.scratch[:0]
	}
	return writeOutput(out.out, append(data, '"'))
}

func (out *jobJSONWriter) stringField(prefix, value string) error {
	if err := writeOutput(out.out, []byte(prefix)); err != nil {
		return err
	}
	return out.writeString(value)
}

func (job jobOutput) writeTo(w io.Writer) error { return job.writeWith(&jobJSONWriter{out: w}) }

func (job jobOutput) writeWith(out *jobJSONWriter) error {
	for _, field := range []struct{ prefix, value string }{
		{`{"id":`, job.job.ID}, {`,"action":`, job.job.Action}, {`,"state":`, job.job.State},
	} {
		if err := out.stringField(field.prefix, field.value); err != nil {
			return err
		}
	}
	for _, data := range [][]byte{[]byte(`,"startedAt":`), job.startedAt, []byte(`,"finishedAt":`), job.finishedAt} {
		if err := writeOutput(out.out, data); err != nil {
			return err
		}
	}
	if job.job.Error != "" {
		if err := out.stringField(`,"error":`, job.job.Error); err != nil {
			return err
		}
	}
	if len(job.job.Result) > 0 {
		var compact bytes.Buffer
		if err := json.Compact(&compact, job.job.Result); err != nil {
			return err
		}
		for _, data := range [][]byte{[]byte(`,"result":`), compact.Bytes()} {
			if err := writeOutput(out.out, data); err != nil {
				return err
			}
		}
	}
	return writeOutput(out.out, []byte("}"))
}

// WriteJobJSON writes a complete workflow snapshot as compact JSON plus newline.
func WriteJobJSON(w io.Writer, job Job) error {
	prepared, err := prepareJobOutput(job, 1)
	if err != nil {
		return err
	}
	if err = prepared.writeTo(w); err != nil {
		return err
	}
	return writeOutput(w, []byte("\n"))
}

// WriteHistoryJSON validates all records before writing the array, then compacts
// one result at a time and streams metadata through one fixed scratch buffer.
// The caller must not mutate jobs or their result bytes during this call.
func WriteHistoryJSON(w io.Writer, jobs []Job) error {
	return writeHistoryJSON(w, jobs, 2)
}

// WriteHistoryReportJSON preserves the API's existing acceptance of every valid
// Job value, including jobs at the decoder's nesting limit. An enclosing report
// may exceed an individual consumer's document-depth limit, as with json.Marshal.
func WriteHistoryReportJSON(w io.Writer, jobs []Job) error {
	return writeHistoryJSON(w, jobs, 1)
}

func writeHistoryJSON(w io.Writer, jobs []Job, nesting int) error {
	prepared := make([]jobOutput, len(jobs))
	for i, job := range jobs {
		var err error
		prepared[i], err = prepareJobOutput(job, nesting)
		if err != nil {
			return err
		}
	}
	if err := writeOutput(w, []byte("[")); err != nil {
		return err
	}
	out := &jobJSONWriter{out: w}
	for i, job := range prepared {
		if i > 0 {
			if err := writeOutput(w, []byte(",")); err != nil {
				return err
			}
		}
		if err := job.writeWith(out); err != nil {
			return err
		}
	}
	return writeOutput(w, []byte("]\n"))
}

// WriteSystemReportJSON streams the existing platform/operations/job response.
// Header and job encoding are validated before any response bytes are written.
func WriteSystemReportJSON(w io.Writer, platform string, job Job) error {
	header, err := json.Marshal(struct {
		Platform   string      `json:"platform"`
		Operations []Operation `json:"operations"`
	}{platform, Catalog()})
	if err != nil {
		return err
	}
	prepared, err := prepareJobOutput(job, 1)
	if err != nil {
		return err
	}
	if err = writeOutput(w, header[:len(header)-1]); err != nil {
		return err
	}
	if err = writeOutput(w, []byte(`,"job":`)); err != nil {
		return err
	}
	if err = prepared.writeTo(w); err != nil {
		return err
	}
	return writeOutput(w, []byte("}\n"))
}
