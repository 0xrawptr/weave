package api

import (
	"encoding/json"
)

func inputJSONResponse(input []byte, rawInput bool) json.RawMessage {
	if len(input) == 0 {
		return nil
	}
	if rawInput {
		return json.RawMessage(input)
	}
	var value interface{}
	if err := json.Unmarshal(input, &value); err != nil {
		return json.RawMessage(input)
	}
	value = sanitizeLargeInput(value)
	out, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(input)
	}
	return json.RawMessage(out)
}

func sanitizeLargeInput(value interface{}) interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			if key == "wordlist" {
				if values, ok := item.([]interface{}); ok && len(values) > 20 {
					out[key] = map[string]interface{}{
						"redacted": true,
						"count":    len(values),
						"sample":   sampleStrings(values, 5),
					}
					continue
				}
			}
			out[key] = sanitizeLargeInput(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, item := range typed {
			out[i] = sanitizeLargeInput(item)
		}
		return out
	default:
		return value
	}
}

func sampleStrings(values []interface{}, limit int) []string {
	if limit <= 0 || len(values) == 0 {
		return nil
	}
	out := make([]string, 0, limit)
	for _, value := range values {
		if len(out) >= limit {
			break
		}
		if s, ok := value.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
