package scogs

import (
	"bufio"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CloudfrontScanner scans Cloudfront logs.
// Uncompress the logs before reading them.
type CloudfrontScanner struct {
	bufio.Scanner
}

// CFLogLine is the struct representing one line of a CF log
// http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat
type CFLogLine struct {
	Comment      bool
	Time         time.Time
	EdgeLocation string
	// ResponseSize in bytes
	ResponseSize int
	ClientIP     net.IP
	Method       string
	Status       int
	CFUrl        url.URL
	AltURL       url.URL
}

// Example date and time: 2016-08-15	06:04:29
const dateTimeFormat = "2006-01-02 15:04:05"

// LogLine parses the current scanner's Text() into a CF log line.
// See http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat
// for indexes.
func (s *CloudfrontScanner) LogLine() CFLogLine {
	if strings.HasPrefix(s.Text(), "#") {
		return CFLogLine{Comment: true}
	}
	text := s.Text()
	text = strings.Trim(text, "\t")
	parts := strings.Split(text, "\t")
	timestamp, _ := time.Parse(dateTimeFormat, strings.Join(parts[0:2], " "))
	responseSize, _ := strconv.Atoi(parts[3])
	return CFLogLine{
		Time:         timestamp,
		EdgeLocation: parts[2],
		ResponseSize: responseSize,
		CFUrl: url.URL{
			Scheme:   parts[16],
			Host:     parts[6],
			Path:     parts[7],
			RawQuery: parts[11],
		},
	}
}

// NewCloudfrontScanner creates a new Cloudfont log scanner with a Reader
func NewCloudfrontScanner(r io.Reader) CloudfrontScanner {
	return CloudfrontScanner{Scanner: *bufio.NewScanner(r)}
}
