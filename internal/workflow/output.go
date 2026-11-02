package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// These private-data exports retain complete result values without indentation,
// HTML escaping or Unicode-separator expansion. Do not embed them in HTML/JS.
// Callers enforce result/history read limits; writer failures may leave partial
// output and must be returned to the operator.
type jobOutput struct {
	metadata []byte
	result   json.RawMessage
}

func prepareJobOutput(job Job, nesting int) (jobOutput, error) {
	result := job.Result
	job.Result = nil
	metadata, err := json.Marshal(job)
	if err != nil {
		return jobOutput{}, err
	}
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
	return jobOutput{metadata: metadata, result: result}, nil
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

func (job jobOutput) writeTo(w io.Writer) error {
	if len(job.result) == 0 {
		return writeOutput(w, job.metadata)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, job.result); err != nil {
		return err
	}
	// Metadata is an encoded Job object with its Result omitted. Only validated
	// compact JSON is inserted into that object's result member.
	for _, data := range [][]byte{job.metadata[:len(job.metadata)-1], []byte(`,"result":`), compact.Bytes(), []byte("}")} {
		if err := writeOutput(w, data); err != nil {
			return err
		}
	}
	return nil
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
// one result at a time instead of allocating a second encoded history buffer.
// The caller must not mutate jobs or their result bytes during this call.
func WriteHistoryJSON(w io.Writer, jobs []Job) error {
	prepared := make([]jobOutput, len(jobs))
	for i, job := range jobs {
		var err error
		prepared[i], err = prepareJobOutput(job, 2)
		if err != nil {
			return err
		}
	}
	if err := writeOutput(w, []byte("[")); err != nil {
		return err
	}
	for i, job := range prepared {
		if i > 0 {
			if err := writeOutput(w, []byte(",")); err != nil {
				return err
			}
		}
		if err := job.writeTo(w); err != nil {
			return err
		}
	}
	return writeOutput(w, []byte("]\n"))
}
