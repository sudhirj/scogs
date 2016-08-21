package scogs

import (
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogfmtScanner(t *testing.T) {
	file, err := os.Open("logfmt1.log")
	if err != nil {
		log.Fatal(err)
	}

	scanner := NewLogfmtScanner(file)
	assert.True(t, scanner.Scan())
	kv := scanner.LogLineKV()
	assert.Equal(t, "sat.sqs.inbox.open", kv["event"])
	assert.Equal(t, "info", kv["level"])
	assert.Equal(t, "2016-08-15T06:11:06Z", kv["time"])

	assert.True(t, scanner.Scan())
	kv = scanner.LogLineKV()
	assert.Equal(t, "550084kB", kv["sample#memory-cached"])
	assert.Equal(t, "REDIS", kv["source"])
	assert.False(t, scanner.Scan())
}
