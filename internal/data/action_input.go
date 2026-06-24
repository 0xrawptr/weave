package data

import "strings"

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
		out := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value != "" {
				out = append(out, value)
			}
		}
		return out
	case []interface{}:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if s, ok := value.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	default:
		return nil
	}
}
