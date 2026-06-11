package artifact

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
	sdkspray "github.com/chainreactors/sdk/spray"
	spraypkg "github.com/chainreactors/spray/pkg"
)

// SprayArtifact wraps the SDK spray engine for HTTP path fuzzing and URL discovery.
type SprayArtifact struct {
	engine         *sdkspray.SprayEngine
	defaultThreads int
	resultHandler  func(ctx context.Context, target, campaignID string, result SprayResultItem)
}

// SprayInput defines the input for spray operations.
type SprayInput struct {
	URLs           []string `json:"urls,omitempty"`          // for check mode
	BaseURLs       []string `json:"base_urls,omitempty"`     // for brute mode
	Wordlist       []string `json:"wordlist,omitempty"`      // for brute mode
	WordlistMode   string   `json:"wordlist_mode,omitempty"` // "full" uses SDK default dictionary
	WordlistOffset int      `json:"wordlist_offset,omitempty"`
	WordlistLimit  int      `json:"wordlist_limit,omitempty"`

	Threads        int      `json:"threads,omitempty"`
	Timeout        int      `json:"timeout,omitempty"`
	Method         string   `json:"method,omitempty"`
	Headers        []string `json:"headers,omitempty"`
	Host           string   `json:"host,omitempty"`
	Mode           string   `json:"mode,omitempty"` // path, host, param
	Filter         string   `json:"filter,omitempty"`
	Match          string   `json:"match,omitempty"`
	Proxies        []string `json:"proxies,omitempty"`
	Advance        bool     `json:"advance,omitempty"`
	ActivePlugin   bool     `json:"active_plugin,omitempty"`
	ReconPlugin    bool     `json:"recon_plugin,omitempty"`
	BakPlugin      bool     `json:"bak_plugin,omitempty"`
	FuzzuliPlugin  bool     `json:"fuzzuli_plugin,omitempty"`
	CommonPlugin   bool     `json:"common_plugin,omitempty"`
	CrawlPlugin    bool     `json:"crawl_plugin,omitempty"`
	CrawlDepth     int      `json:"crawl_depth,omitempty"`
	Finger         bool     `json:"finger,omitempty"`
	Extracts       []string `json:"extracts,omitempty"`
	RecursiveDepth int      `json:"recursive_depth,omitempty"`
	Dictionaries   []string `json:"dictionaries,omitempty"`
	Rules          []string `json:"rules,omitempty"`
	Word           string   `json:"word,omitempty"`
	DefaultDict    bool     `json:"default_dict,omitempty"`
}

// SprayOutput contains the spray results.
type SprayOutput struct {
	Results []SprayResultItem `json:"results"`
	Total   int               `json:"total"`
}

type SpraySummary struct {
	Total     int               `json:"total"`
	Sample    []SprayResultItem `json:"sample,omitempty"`
	Truncated bool              `json:"truncated"`
}

// SprayResultItem is a flattened spray result.
type SprayResultItem struct {
	URL           string               `json:"url"`
	StatusCode    int                  `json:"status_code"`
	Title         string               `json:"title,omitempty"`
	ContentType   string               `json:"content_type,omitempty"`
	ContentLength int64                `json:"content_length,omitempty"`
	BodyHash      string               `json:"body_hash,omitempty"`
	BodySimhash   string               `json:"body_simhash,omitempty"`
	FaviconHash   string               `json:"favicon_hash,omitempty"`
	RedirectURL   string               `json:"location,omitempty"`
	Source        string               `json:"source,omitempty"`
	Valid         bool                 `json:"valid"`
	Fuzzy         bool                 `json:"fuzzy,omitempty"`
	Reason        string               `json:"reason,omitempty"`
	Frameworks    []SprayFrameworkItem `json:"frameworks,omitempty"`
	Extracts      []SprayExtractItem   `json:"extracts,omitempty"`
}

type SprayFrameworkItem struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	IsFocus     bool                   `json:"is_focus,omitempty"`
	MatchDetail map[string]interface{} `json:"match_detail,omitempty"`
}

type SprayExtractItem struct {
	Name     string   `json:"name"`
	Severity string   `json:"severity,omitempty"`
	Values   []string `json:"values,omitempty"`
}

// NewSprayArtifactFromEngine wraps an already-initialized SDK engine.
func NewSprayArtifactFromEngine(engine *sdkspray.SprayEngine) *SprayArtifact {
	return &SprayArtifact{engine: engine}
}

func (s *SprayArtifact) SetDefaultThreads(threads int) {
	if threads > 0 {
		s.defaultThreads = threads
	}
}

func (s *SprayArtifact) SetResultHandler(h func(ctx context.Context, target, campaignID string, result SprayResultItem)) {
	s.resultHandler = h
}

func (s *SprayArtifact) Name() string { return "spray" }

func (s *SprayArtifact) Descriptor() Descriptor {
	return Descriptor{
		Name:          s.Name(),
		Consumes:      []string{"url", "wordlist"},
		Produces:      []string{"url"},
		Passive:       false,
		TouchesTarget: true,
		Risk:          "medium",
		Description:   "HTTP path discovery and URL checking",
	}
}

func (s *SprayArtifact) InputSchema() InputSchema {
	return InputSchema{
		Fields: []SchemaField{
			{Name: "urls", Type: "[]string", Required: false, Description: "URLs to check"},
			{Name: "base_urls", Type: "[]string", Required: false, Description: "Base URLs for brute force"},
			{Name: "wordlist", Type: "[]string", Required: false, Description: "Wordlist for path brute force"},
			{Name: "wordlist_mode", Type: "string", Required: false, Description: "Wordlist mode, e.g. full"},
			{Name: "wordlist_offset", Type: "int", Required: false, Description: "Offset into the selected wordlist"},
			{Name: "wordlist_limit", Type: "int", Required: false, Description: "Maximum words to use from the selected wordlist"},
			{Name: "threads", Type: "int", Required: false, Description: "Worker threads"},
			{Name: "timeout", Type: "int", Required: false, Description: "HTTP timeout in seconds"},
			{Name: "method", Type: "string", Required: false, Description: "HTTP method"},
			{Name: "headers", Type: "[]string", Required: false, Description: "Custom headers"},
			{Name: "host", Type: "string", Required: false, Description: "Custom Host header"},
			{Name: "mode", Type: "string", Required: false, Description: "Spray mode: path, host, param"},
			{Name: "filter", Type: "string", Required: false, Description: "Filter expression"},
			{Name: "match", Type: "string", Required: false, Description: "Match expression"},
			{Name: "proxies", Type: "[]string", Required: false, Description: "Execution proxy chain"},
			{Name: "advance", Type: "bool", Required: false, Description: "Enable all plugins"},
			{Name: "active_plugin", Type: "bool", Required: false, Description: "Enable active fingerprint path plugin"},
			{Name: "recon_plugin", Type: "bool", Required: false, Description: "Enable recon extractors"},
			{Name: "bak_plugin", Type: "bool", Required: false, Description: "Enable backup-file discovery"},
			{Name: "fuzzuli_plugin", Type: "bool", Required: false, Description: "Enable fuzzuli plugin"},
			{Name: "common_plugin", Type: "bool", Required: false, Description: "Enable common-file discovery"},
			{Name: "crawl_plugin", Type: "bool", Required: false, Description: "Enable crawler plugin"},
			{Name: "crawl_depth", Type: "int", Required: false, Description: "Crawler depth"},
			{Name: "finger", Type: "bool", Required: false, Description: "Enable active fingerprinting"},
			{Name: "extracts", Type: "[]string", Required: false, Description: "Extractor groups"},
			{Name: "recursive_depth", Type: "int", Required: false, Description: "Recursive depth"},
			{Name: "dictionaries", Type: "[]string", Required: false, Description: "Dictionary names"},
			{Name: "rules", Type: "[]string", Required: false, Description: "Rule names"},
			{Name: "word", Type: "string", Required: false, Description: "Single fuzz word"},
			{Name: "default_dict", Type: "bool", Required: false, Description: "Use SDK default dictionary"},
		},
	}
}

func (s *SprayArtifact) OutputSchema() OutputSchema {
	return OutputSchema{
		Fields: []SchemaField{
			{Name: "results", Type: "array", Required: false, Description: "URL check or brute results"},
			{Name: "total", Type: "int", Required: false, Description: "Total number of results"},
		},
	}
}

func (s *SprayArtifact) Execute(ctx context.Context, input Input) (Output, error) {
	var sprayIn SprayInput
	if err := json.Unmarshal(input.Data, &sprayIn); err != nil {
		return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
	}

	started := time.Now()
	collector := newStatCollector(func(latest ExecutionStat, count int) {
		recordArtifactHeartbeat(ctx, s.Name(), input.Target, "sdk_stats", started, statHeartbeatFields(latest, count))
	})
	if sprayIn.Threads <= 0 {
		sprayIn.Threads = s.defaultThreads
	}

	if len(sprayIn.BaseURLs) > 0 && strings.EqualFold(sprayIn.WordlistMode, "full") {
		if len(sprayIn.Wordlist) == 0 {
			sprayIn.Wordlist = defaultSprayWordlist()
			sprayIn.Wordlist = sliceWordlist(sprayIn.Wordlist, sprayIn.WordlistOffset, sprayIn.WordlistLimit)
		}
		sprayIn.DefaultDict = false
	}
	if len(sprayIn.BaseURLs) > 0 && sprayIn.DefaultDict && len(sprayIn.Wordlist) == 0 {
		sprayIn.Wordlist = defaultSprayWordlist()
		sprayIn.DefaultDict = false
	}
	if len(sprayIn.BaseURLs) > 0 && (strings.EqualFold(sprayIn.WordlistMode, "full") || sprayIn.DefaultDict) && len(sprayIn.Wordlist) == 0 {
		return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: "default spray wordlist is empty"}, nil
	}

	sprayCtx := configureSprayContext(sdkspray.NewContext().WithContext(ctx).SetStatsHandler(collector.Handler()), sprayIn)

	var items []SprayResultItem

	if len(sprayIn.BaseURLs) > 0 && (len(sprayIn.Wordlist) > 0 || sprayIn.DefaultDict || len(sprayIn.Dictionaries) > 0 || sprayIn.Word != "" || len(sprayIn.Rules) > 0) {
		recordArtifactHeartbeat(ctx, s.Name(), input.Target, "brute", started, map[string]interface{}{
			"base_urls": len(sprayIn.BaseURLs),
			"wordlist":  len(sprayIn.Wordlist),
			"default":   sprayIn.DefaultDict,
			"threads":   sprayIn.Threads,
		})
		resultCh, err := s.engine.Execute(sprayCtx, sdkspray.NewBruteTasks(sprayIn.BaseURLs, sprayIn.Wordlist))
		if err != nil {
			return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for r := range resultCh {
			data, ok := sdktypes.ResultData[*sdktypes.SprayResult](r)
			if !ok || data == nil {
				continue
			}
			item := sprayResultItem(data)
			items = append(items, item)
			s.emitResult(ctx, input, item)
		}
	} else if len(sprayIn.URLs) > 0 {
		recordArtifactHeartbeat(ctx, s.Name(), input.Target, "check", started, map[string]interface{}{
			"urls":    len(sprayIn.URLs),
			"threads": sprayIn.Threads,
		})
		resultCh, err := s.engine.Execute(sprayCtx, sdkspray.NewCheckTask(sprayIn.URLs))
		if err != nil {
			return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: err.Error()}, nil
		}
		for r := range resultCh {
			data, ok := sdktypes.ResultData[*sdktypes.SprayResult](r)
			if !ok || data == nil {
				continue
			}
			item := sprayResultItem(data)
			items = append(items, item)
			s.emitResult(ctx, input, item)
		}
	} else {
		return Output{Artifact: s.Name(), Target: input.Target, Success: false, Error: "no valid input: provide urls or base_urls+wordlist"}, nil
	}
	recordArtifactHeartbeat(ctx, s.Name(), input.Target, "completed", started, map[string]interface{}{
		"results": len(items),
	})

	fullData, _ := json.Marshal(SprayOutput{Results: items, Total: len(items)})
	summaryData, _ := json.Marshal(spraySummary(items))
	return Output{
		Artifact: s.Name(),
		Target:   input.Target,
		Success:  true,
		Data:     summaryData,
		FullData: fullData,
		Stats:    collector.Stats(),
	}, nil
}

func (s *SprayArtifact) Close() error {
	return s.engine.Close()
}

func (s *SprayArtifact) emitResult(ctx context.Context, input Input, item SprayResultItem) {
	if s.resultHandler != nil && item.URL != "" {
		s.resultHandler(ctx, input.Target, input.CampaignID, item)
	}
}

func FullSprayWordlist() []string {
	return defaultSprayWordlist()
}

func defaultSprayWordlist() []string {
	if len(spraypkg.Dicts["default"]) == 0 {
		_ = spraypkg.Load()
	}
	seen := make(map[string]bool)
	var words []string
	for _, word := range spraypkg.Dicts["default"] {
		if word == "" || seen[word] {
			continue
		}
		seen[word] = true
		words = append(words, word)
	}
	return words
}

func sliceWordlist(words []string, offset, limit int) []string {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(words) {
		return nil
	}
	end := len(words)
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return append([]string{}, words[offset:end]...)
}

func configureSprayContext(sprayCtx *sdkspray.Context, input SprayInput) *sdkspray.Context {
	if input.Threads > 0 {
		sprayCtx.SetThreads(input.Threads)
	}
	if input.Timeout > 0 {
		sprayCtx.SetTimeout(input.Timeout)
	}
	if input.Method != "" {
		sprayCtx.SetMethod(input.Method)
	}
	if len(input.Headers) > 0 {
		sprayCtx.SetHeaders(input.Headers)
	}
	if input.Host != "" {
		sprayCtx.SetHost(input.Host)
	}
	if input.Mode != "" {
		sprayCtx.SetMod(input.Mode)
	}
	if input.Filter != "" {
		sprayCtx.SetFilter(input.Filter)
	}
	if input.Match != "" {
		sprayCtx.SetMatch(input.Match)
	}
	if len(input.Proxies) > 0 {
		sprayCtx.SetProxy(input.Proxies...)
	}
	if input.Advance {
		sprayCtx.SetAdvance(true)
	}
	if input.ActivePlugin {
		sprayCtx.SetActivePlugin(true)
	}
	if input.ReconPlugin {
		sprayCtx.SetReconPlugin(true)
	}
	if input.BakPlugin {
		sprayCtx.SetBakPlugin(true)
	}
	if input.FuzzuliPlugin {
		sprayCtx.SetFuzzuliPlugin(true)
	}
	if input.CommonPlugin {
		sprayCtx.SetCommonPlugin(true)
	}
	if input.CrawlPlugin {
		sprayCtx.SetCrawlPlugin(true)
	}
	if input.CrawlDepth > 0 {
		sprayCtx.SetCrawlDepth(input.CrawlDepth)
	}
	if input.Finger {
		sprayCtx.SetFinger(true)
	}
	if len(input.Extracts) > 0 {
		sprayCtx.SetExtracts(input.Extracts)
	}
	if input.RecursiveDepth > 0 {
		sprayCtx.SetRecursiveDepth(input.RecursiveDepth)
	}
	if len(input.Dictionaries) > 0 {
		sprayCtx.SetDictionaries(input.Dictionaries)
	}
	if len(input.Rules) > 0 {
		sprayCtx.SetRules(input.Rules)
	}
	if input.Word != "" {
		sprayCtx.SetWord(input.Word)
	}
	if input.DefaultDict {
		sprayCtx.SetDefaultDict(true)
	}
	return sprayCtx
}

func spraySummary(items []SprayResultItem) SpraySummary {
	const sampleLimit = 20
	summary := SpraySummary{Total: len(items)}
	if len(items) > sampleLimit {
		summary.Sample = append([]SprayResultItem(nil), items[:sampleLimit]...)
		summary.Truncated = true
		return summary
	}
	summary.Sample = append([]SprayResultItem(nil), items...)
	return summary
}

func sprayResultItem(r *sdktypes.SprayResult) SprayResultItem {
	if r == nil {
		return SprayResultItem{}
	}
	item := SprayResultItem{
		URL:           r.UrlString,
		StatusCode:    r.Status,
		Title:         r.Title,
		ContentType:   r.ContentType,
		ContentLength: int64(r.BodyLength),
		RedirectURL:   r.RedirectURL,
		Valid:         r.IsValid,
		Fuzzy:         r.IsFuzzy,
		Reason:        r.Reason,
	}
	item.Source = r.Source.Name()
	if r.Hashes != nil {
		item.BodyHash = r.Hashes.BodyMd5
		item.BodySimhash = r.Hashes.BodySimhash
		if looksLikeFaviconResult(r.UrlString, r.ContentType) {
			item.FaviconHash = r.Hashes.BodyMmh3
		}
	}
	item.Frameworks = sprayFrameworkItems(r)
	item.Extracts = sprayExtractItems(r)
	return item
}

func sprayFrameworkItems(r *sdktypes.SprayResult) []SprayFrameworkItem {
	if r == nil || len(r.Frameworks) == 0 {
		return nil
	}
	items := make([]SprayFrameworkItem, 0, len(r.Frameworks))
	for name, fw := range r.Frameworks {
		if fw == nil {
			continue
		}
		item := SprayFrameworkItem{
			Name:    fw.Name,
			Tags:    append([]string(nil), fw.Tags...),
			IsFocus: fw.IsFocus,
		}
		if item.Name == "" {
			item.Name = name
		}
		if fw.Attributes != nil {
			item.Version = fw.Version
		}
		if fw.MatchDetail != nil {
			item.MatchDetail = map[string]interface{}{
				"rule_index":    fw.MatchDetail.RuleIndex,
				"matcher_type":  fw.MatchDetail.MatcherType,
				"matcher_index": fw.MatchDetail.MatcherIndex,
				"matcher_value": fw.MatchDetail.MatcherValue,
				"send_data":     fw.MatchDetail.SendData,
			}
		}
		items = append(items, item)
	}
	if len(items) == 0 {
		return nil
	}
	return items
}

func sprayExtractItems(r *sdktypes.SprayResult) []SprayExtractItem {
	if r == nil || len(r.Extracteds) == 0 {
		return nil
	}
	items := make([]SprayExtractItem, 0, len(r.Extracteds))
	for _, extracted := range r.Extracteds {
		if extracted == nil {
			continue
		}
		items = append(items, SprayExtractItem{
			Name:     extracted.Name,
			Severity: extracted.Severity,
			Values:   append([]string(nil), extracted.ExtractResult...),
		})
	}
	return items
}

func looksLikeFaviconResult(rawURL, contentType string) bool {
	contentType = strings.ToLower(contentType)
	if strings.Contains(contentType, "icon") || strings.Contains(contentType, "ico") {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p := strings.ToLower(u.Path)
	return strings.HasSuffix(p, "/favicon.ico") || strings.Contains(p, "favicon")
}
