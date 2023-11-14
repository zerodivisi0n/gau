package output

import (
	"io"
	"net/url"
	"path"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/bytebufferpool"
)

type Result struct {
	URL      string `json:"url"`
	Provider string `json:"provider"`
}

func WriteURLs(writer io.Writer, results <-chan Result, blacklistMap mapset.Set[string], RemoveParameters bool) error {
	lastURL := mapset.NewThreadUnsafeSet[string]()
	for result := range results {
		buf := bytebufferpool.Get()
		u, err := url.Parse(result.URL)
		if err != nil {
			continue
		}
		if path.Ext(u.Path) != "" && blacklistMap.Contains(strings.ToLower(path.Ext(u.Path))) {
			continue
		}

		if RemoveParameters && !lastURL.Contains(u.Host+u.Path) {
			continue
		}
		lastURL.Add(u.Host + u.Path)

		buf.B = append(buf.B, []byte(result.URL)...)
		buf.B = append(buf.B, "\n"...)
		_, err = writer.Write(buf.B)
		if err != nil {
			return err
		}
		bytebufferpool.Put(buf)
	}
	return nil
}

func WriteURLsJSON(writer io.Writer, results <-chan Result, blacklistMap mapset.Set[string], RemoveParameters bool) {
	enc := jsoniter.NewEncoder(writer)
	for result := range results {
		u, err := url.Parse(result.URL)
		if err != nil {
			continue
		}
		if blacklistMap.Contains(strings.ToLower(path.Ext(u.Path))) {
			continue
		}
		if err := enc.Encode(result); err != nil {
			// todo: handle this error
			continue
		}
	}
}
