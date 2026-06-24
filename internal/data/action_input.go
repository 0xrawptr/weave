package data

import "strings"

func CleanStrings(values []string, dedup bool) []string {
	out := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if dedup {
			if seen[value] {
				continue
			}
			seen[value] = true
		}
		out = append(out, value)
	}
	return out
}

func SplitList(raw string, dedup bool) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	return CleanStrings(parts, dedup)
}

func ActionInputStrings(input map[string]interface{}, field string) []string {
	if len(input) == 0 {
		return nil
	}
	switch values := input[field].(type) {
	case string:
		value := strings.TrimSpace(values)
		if value == "" {
			return nil
		}
		return []string{value}
	case []string:
		return CleanStrings(values, false)
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := value.(string); ok {
				out = append(out, s)
			}
		}
		return CleanStrings(out, false)
	default:
		return nil
	}
}

func ChunkStrings(values []string, size int, dedup bool) [][]string {
	values = CleanStrings(values, dedup)
	if len(values) == 0 {
		return nil
	}
	if size <= 0 || size >= len(values) {
		return [][]string{values}
	}
	chunks := make([][]string, 0, (len(values)+size-1)/size)
	for start := 0; start < len(values); start += size {
		end := start + size
		if end > len(values) {
			end = len(values)
		}
		chunks = append(chunks, append([]string{}, values[start:end]...))
	}
	return chunks
}
