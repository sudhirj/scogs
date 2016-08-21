package scogs

import (
	"bufio"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CloudFrontLogScanner extends a bufio.Scanner with CloudFront log reading cababilities.
type CloudFrontLogScanner struct {
	bufio.Scanner
}

// CloudFrontLogLine is the struct representing one line of a CF log.
type CloudFrontLogLine struct {
	Comment       bool
	Timestamp     time.Time
	EdgeLocation  string
	ResponseSize  int // in bytes
	Method        string
	Status        int
	CloudFrontURL url.URL
	AccessURL     url.URL
	ResultType    string
	Referer       string
	TimeTaken     float64 // in seconds
	EdgeRequestID string
}

// Example date and time: 2016-08-15	06:04:29
const dateTimeFormat = "2006-01-02 15:04:05"

// LogLine parses the current scanner's Text() into a CF log line.
// See http://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html#BasicDistributionFileFormat for information about fields.
func (s *CloudFrontLogScanner) LogLine() CloudFrontLogLine {
	if strings.HasPrefix(s.Text(), "#") {
		return CloudFrontLogLine{Comment: true}
	}
	text := s.Text()
	text = strings.Trim(text, "\t")
	parts := strings.Split(text, "\t")
	dateAndTime := parts[0:2] // date, time
	timestamp, _ := time.Parse(dateTimeFormat, strings.Join(dateAndTime, " "))
	responseSize, _ := strconv.Atoi(parts[3])         // sc-bytes
	timeTaken, _ := strconv.ParseFloat(parts[18], 64) // time-taken
	return CloudFrontLogLine{
		Timestamp:    timestamp,
		EdgeLocation: parts[2],     // x-edge-location
		ResponseSize: responseSize, // sc-bytes
		CloudFrontURL: url.URL{
			Scheme:   parts[16], // cs-protocol
			Host:     parts[6],  // cs(Host)
			Path:     parts[7],  // cs-uri-stem
			RawQuery: parts[11], // cs-uri-query
		},
		AccessURL: url.URL{
			Scheme:   parts[16], // cs-protocol
			Host:     parts[15], // x-host-header
			Path:     parts[7],  // cs-uri-stem
			RawQuery: parts[11], // cs-uri-query
		},
		Method:        parts[5],  // cs-method
		ResultType:    parts[13], // x-edge-result-type
		Referer:       parts[9],  // cs(Referer)
		TimeTaken:     timeTaken, // time-taken
		EdgeRequestID: parts[14], // x-edge-request-id
	}
}

// NewCloudFrontScanner creates a new CloudFront log scanner with a Reader.
// The reader must point to an uncompressed CloudFront log.
func NewCloudFrontScanner(r io.Reader) CloudFrontLogScanner {
	return CloudFrontLogScanner{Scanner: *bufio.NewScanner(r)}
}
