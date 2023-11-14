package wayback

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/lc/gau/v2/pkg/httpclient"
	"github.com/lc/gau/v2/pkg/output"
	"github.com/lc/gau/v2/pkg/providers"
	"github.com/sirupsen/logrus"
)

const (
	Name = "wayback"
)

// verify interface compliance
var _ providers.Provider = (*Client)(nil)

// Client is the structure that holds the WaybackFilters and the Client's configuration
type Client struct {
	filters providers.Filters
	config  *providers.Config
	setter  FieldsSetter
}

func New(config *providers.Config, filters providers.Filters) *Client {
	return &Client{
		filters: filters,
		config:  config,
		setter:  NewFieldsSetter(config),
	}
}

func (c *Client) Name() string {
	return Name
}

// waybackResult holds the response from the wayback API
type waybackResult [][]string

// Fetch fetches all urls for a given domain and sends them to a channel.
// It returns an error should one occur.
func (c *Client) Fetch(ctx context.Context, domain string, results chan output.Result) error {
	pages, err := c.getPagination(domain)
	if err != nil {
		return fmt.Errorf("failed to fetch wayback pagination: %s", err)
	}

	for page := uint(0); page < pages; page++ {
		select {
		case <-ctx.Done():
			return nil
		default:
			logrus.WithFields(logrus.Fields{"provider": Name, "page": page}).Infof("fetching %s", domain)
			apiURL := c.formatURL(domain, page)
			// make HTTP request
			resp, err := httpclient.MakeRequest(c.config.Client, apiURL, c.config.MaxRetries, c.config.Timeout)
			if err != nil {
				return fmt.Errorf("failed to fetch wayback results page %d: %s", page, err)
			}

			var result waybackResult
			if err = jsoniter.Unmarshal(resp, &result); err != nil {
				return fmt.Errorf("failed to decode wayback results for page %d: %s", page, err)
			}

			// check if there's results, wayback's pagination response
			// is not always correct when using a filter
			if len(result) == 0 {
				break
			}

			// output results
			// Slicing as [1:] to skip first result by default
			for _, entry := range result[1:] {
				res := output.Result{
					URL:      entry[0],
					Provider: Name,
				}
				c.setter.Set(entry, &res)
				results <- res
			}
		}
	}
	return nil
}

// formatUrl returns a formatted URL for the Wayback API
func (c *Client) formatURL(domain string, page uint) string {
	if c.config.IncludeSubdomains {
		domain = "*." + domain
	}
	filterParams := c.filters.GetParameters(true)

	return fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&collapse=urlkey&fl=%s&page=%d",
		domain, strings.Join(c.setter.Fields, ","), page,
	) + filterParams
}

// getPagination returns the number of pages for Wayback
func (c *Client) getPagination(domain string) (uint, error) {
	url := fmt.Sprintf("%s&showNumPages=true", c.formatURL(domain, 0))
	resp, err := httpclient.MakeRequest(c.config.Client, url, c.config.MaxRetries, c.config.Timeout)

	if err != nil {
		return 0, err
	}

	var paginationResult uint

	if err = jsoniter.Unmarshal(resp, &paginationResult); err != nil {
		return 0, err
	}

	return paginationResult, nil
}

type FieldsSetter struct {
	Fields []string

	TimestampIndex     int
	ContentTypeIndex   int
	StatusCodeIndex    int
	ContentLengthIndex int
}

func NewFieldsSetter(c *providers.Config) FieldsSetter {
	fs := FieldsSetter{}
	fs.Fields = make([]string, 0, 1+len(c.ExtraFields))
	fs.Fields = append(fs.Fields, "original")

	for _, f := range c.ExtraFields {
		switch f {
		case "timestamp":
			fs.TimestampIndex = len(fs.Fields)
			fs.Fields = append(fs.Fields, "timestamp")
		case "content_type":
			fs.ContentTypeIndex = len(fs.Fields)
			fs.Fields = append(fs.Fields, "mimetype")
		case "status_code":
			fs.StatusCodeIndex = len(fs.Fields)
			fs.Fields = append(fs.Fields, "statuscode")
		case "content_length":
			fs.ContentLengthIndex = len(fs.Fields)
			fs.Fields = append(fs.Fields, "length")
		default:
			logrus.Warnf("unknown extra field %s", f)
		}
	}

	return fs
}

func (s FieldsSetter) Set(entry []string, result *output.Result) {
	var err error
	if index := s.TimestampIndex; index > 0 {
		result.Timestamp, err = time.ParseInLocation("20060102150405", entry[index], time.UTC)
		if err != nil {
			logrus.Warnf("failed to parse timestamp field %s: %v", entry[index], err)
		}
	}
	if index := s.ContentTypeIndex; index > 0 {
		result.ContentType = entry[index]
	}
	if index := s.StatusCodeIndex; index > 0 {
		result.StatusCode, err = strconv.Atoi(entry[index])
		if err != nil {
			logrus.Warnf("failed to parse status code field %s: %v", entry[index], err)
		}
	}
	if index := s.ContentLengthIndex; index > 0 {
		result.ContentLength, err = strconv.Atoi(entry[index])
		if err != nil {
			logrus.Warnf("failed to parse content length field %s: %v", entry[index], err)
		}
	}
}
