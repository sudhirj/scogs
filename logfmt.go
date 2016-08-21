package scogs

import (
	"bufio"
	"io"
	"strings"

	"github.com/go-logfmt/logfmt"
)

// LogfmtScanner extends a bufio.Scanner to make it capable of parsing Logfmt formatted logs.
type LogfmtScanner struct {
	bufio.Scanner
}

// LogfmtKV is a string to string map that represents a single logfmt log line.
type LogfmtKV map[string]string

// LogLineKV reads the current logfmt log line into a LogfmtKV
func (s *LogfmtScanner) LogLineKV() LogfmtKV {
	kv := make(LogfmtKV)
	d := logfmt.NewDecoder(strings.NewReader(s.Text()))
	for d.ScanRecord() {
		for d.ScanKeyval() {
			kv[string(d.Key())] = string(d.Value())
		}
	}
	return kv
}

// NewLogfmtScanner creates a new logfmt scanner from the given reader. Assumes the stream is uncompressed.
func NewLogfmtScanner(r io.Reader) LogfmtScanner {
	return LogfmtScanner{Scanner: *bufio.NewScanner(r)}
}
