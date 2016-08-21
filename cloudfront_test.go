package scogs

import (
	"compress/gzip"
	"log"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCloudfrontScanner(t *testing.T) {
	file, err := os.Open("CF.gz")
	if err != nil {
		log.Fatal(err)
	}
	uncompressedFile, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}
	scanner := NewCloudFrontScanner(uncompressedFile)
	assert.True(t, scanner.Scan()) // Version line
	assert.True(t, scanner.LogLine().Comment)
	assert.True(t, scanner.Scan()) // Fields line
	assert.True(t, scanner.LogLine().Comment)

	assert.True(t, scanner.Scan())
	// #Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status cs(Referer) cs(User-Agent) cs-uri-query cs(Cookie) x-edge-result-type x-edge-request-id x-host-header cs-protocol cs-bytes time-taken x-forwarded-for ssl-protocol ssl-cipher x-edge-response-result-type cs-protocol-version
	// 2016-08-15	06:04:29	SIN2	540648	122.164.17.87	GET	d1duf439t6fjmt.cloudfront.net	/4KUWWncQLgawVXcgfj7JDd/1WcELVj08seEinr6dQuG2m	200	-	Mozilla/5.0%2520(Macintosh;%2520Intel%2520Mac%2520OS%2520X%252010_12_0)%2520AppleWebKit/537.36%2520(KHTML,%2520like%2520Gecko)%2520Chrome/52.0.2743.116%2520Safari/537.36	w=1200&q=90	-	Miss	GfzAdDRQWYNqs8-5jUjOwlSasGFHS93uMOX7u-VFWXYdQRNASzUb8g==	sgn.rw7.io	https	441	4.988	-	TLSv1.2	ECDHE-RSA-AES128-GCM-SHA256	Miss	HTTP/1.1
	l := scanner.LogLine()
	assert.Equal(t, 2016, l.Timestamp.Year())
	assert.Equal(t, 15, l.Timestamp.Day())
	assert.Equal(t, 29, l.Timestamp.Second())

	assert.Equal(t, "SIN2", l.EdgeLocation)
	assert.Equal(t, 540648, l.ResponseSize)
	expectedCFUrl, _ := url.Parse("https://d1duf439t6fjmt.cloudfront.net/4KUWWncQLgawVXcgfj7JDd/1WcELVj08seEinr6dQuG2m?w=1200&q=90")
	assert.Equal(t, *expectedCFUrl, l.CloudFrontURL)

	expectedAltURL, _ := url.Parse("https://sgn.rw7.io/4KUWWncQLgawVXcgfj7JDd/1WcELVj08seEinr6dQuG2m?w=1200&q=90")
	assert.Equal(t, *expectedAltURL, l.AccessURL)

	assert.Equal(t, "GET", l.Method)
	assert.Equal(t, "Miss", l.ResultType)
	assert.Equal(t, "-", l.Referer)
	assert.Equal(t, 4.988, l.TimeTaken)
	assert.Equal(t, "GfzAdDRQWYNqs8-5jUjOwlSasGFHS93uMOX7u-VFWXYdQRNASzUb8g==", l.EdgeRequestID)
}
