package favicon

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chainreactors/utils/encode"
)

// Fetcher 只负责下载 favicon，不做识别
type Fetcher struct {
	client *http.Client
}

// Result 下载结果
type Result struct {
	TargetURL  string
	FaviconURL string
	Data       []byte
	Size       int
	Source     string // html-link / default-path / data-uri / root-fallback
	HashMMH3   string // FOFA 标准的 favicon hash，用于图标聚合搜索
}

// NewFetcher 创建下载器
func NewFetcher() *Fetcher {
	return &Fetcher{
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// ExtractFromHTML 使用已有的 HTML 内容下载 favicon，不重复请求目标页面
func ExtractFromHTML(htmlBody []byte, target string) (*Result, error) {
	return NewFetcher().prepareResult(bytes.NewReader(htmlBody), target)
}

// Fetch 访问目标 → 解析HTML → 下载 favicon → 返回原始数据
func (f *Fetcher) Fetch(target string) (*Result, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	req, _ := http.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch target failed: %w", err)
	}
	defer resp.Body.Close()

	return f.prepareResult(resp.Body, target)
}

func (f *Fetcher) prepareResult(htmlBody io.Reader, target string) (*Result, error) {
	result := &Result{TargetURL: target}

	candidates, resolveBase := f.extractCandidates(htmlBody, target)

	if len(candidates) == 0 {
		u, _ := url.Parse(target)
		candidates = append(candidates, fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host))
		result.Source = "default-path"
	} else {
		result.Source = "html-link"
	}

	iconData, iconURL := f.downloadIcon(candidates, resolveBase, target)
	if len(iconData) == 0 && result.Source != "default-path" {
		u, _ := url.Parse(target)
		rootIcon := fmt.Sprintf("%s://%s/favicon.ico", u.Scheme, u.Host)
		if data, url2 := f.downloadIcon([]string{rootIcon}, resolveBase, target); len(data) > 0 {
			iconData, iconURL = data, url2
			result.Source = "root-fallback"
		}
	}

	if len(iconData) == 0 {
		return nil, fmt.Errorf("all favicon download attempts failed")
	}

	result.FaviconURL = iconURL
	result.Data = iconData
	result.Size = len(iconData)
	result.HashMMH3 = encode.Mmh3Hash32(iconData)
	return result, nil
}

// extractCandidates 提取候选 favicon URL，同时检测 <base href> 并返回解析用的 base
func (f *Fetcher) extractCandidates(r io.Reader, baseURL string) ([]string, string) {
	doc, err := goquery.NewDocumentFromReader(r)
	if err != nil {
		return nil, baseURL
	}

	// 检查 <base href>，如果存在则用它作为 resolve 的 base
	resolveBase := baseURL
	if base, exists := doc.Find("base").Attr("href"); exists {
		if resolved := resolveURL(baseURL, strings.TrimSpace(base)); resolved != "" {
			resolveBase = resolved
		}
	}

	var candidates []string

	doc.Find("link[rel]").Each(func(i int, s *goquery.Selection) {
		rel := strings.ToLower(strings.TrimSpace(s.AttrOr("rel", "")))
		href := strings.TrimSpace(s.AttrOr("href", ""))
		if href == "" {
			return
		}

		for _, tok := range strings.Fields(rel) {
			switch tok {
			case "icon", "shortcut", "shortcut-icon",
				"apple-touch-icon", "mask-icon", "alternate":
				candidates = append(candidates, href)
				return
			}
		}
	})

	sort.SliceStable(candidates, func(i, j int) bool {
		ai := strings.HasSuffix(strings.ToLower(stripQuery(candidates[i])), ".ico")
		aj := strings.HasSuffix(strings.ToLower(stripQuery(candidates[j])), ".ico")
		if ai == aj {
			return candidates[i] < candidates[j]
		}
		return ai && !aj
	})

	seen := make(map[string]bool)
	uniq := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if !seen[c] {
			seen[c] = true
			uniq = append(uniq, c)
		}
	}
	return uniq, resolveBase
}

func (f *Fetcher) parseDataURI(uri string) ([]byte, error) {
	commaIdx := strings.Index(uri, ",")
	if commaIdx == -1 {
		return nil, fmt.Errorf("invalid data URI")
	}
	return base64.StdEncoding.DecodeString(uri[commaIdx+1:])
}

func (f *Fetcher) downloadIcon(candidates []string, resolveBase string, target string) ([]byte, string) {
	attempts := 0
	for _, candidate := range candidates {
		if attempts >= 2 {
			break
		}
		attempts++
		resolved := resolveURL(resolveBase, candidate)

		if strings.HasPrefix(resolved, "data:") {
			if data, err := f.parseDataURI(resolved); err == nil && len(data) > 0 {
				return data, resolved
			}
			continue
		}

		iconReq, _ := http.NewRequest("GET", resolved, nil)
		iconReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		iconReq.Header.Set("Referer", target)

		if iconResp, err := f.client.Do(iconReq); err == nil {
			data, _ := io.ReadAll(iconResp.Body)
			iconResp.Body.Close()
			if iconResp.StatusCode == 200 && len(data) > 0 {
				return data, resolved
			}
		}

		if !strings.HasPrefix(candidate, "/") {
			retryResolved := resolveURL(resolveBase, "/"+candidate)
			if retryResolved != resolved {
				iconReq, _ = http.NewRequest("GET", retryResolved, nil)
				iconReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
				iconReq.Header.Set("Referer", target)
				if iconResp, err := f.client.Do(iconReq); err == nil {
					data, _ := io.ReadAll(iconResp.Body)
					iconResp.Body.Close()
					if iconResp.StatusCode == 200 && len(data) > 0 {
						return data, retryResolved
					}
				}
			}
		}
	}
	return nil, ""
}

func stripQuery(href string) string {
	if i := strings.Index(href, "?"); i != -1 {
		return href[:i]
	}
	return href
}

func resolveURL(base, href string) string {
	if strings.HasPrefix(href, "http://") ||
		strings.HasPrefix(href, "https://") ||
		strings.HasPrefix(href, "data:") {
		return href
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return href
	}
	ref, err := url.Parse(href)
	if err != nil {
		return href
	}
	return baseURL.ResolveReference(ref).String()
}
