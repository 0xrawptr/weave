package workflow

import "encoding/json"

func mustMarshal(v interface{}) []byte {
	raw, _ := json.Marshal(v)
	return raw
}

func mapAnyToInterface(in map[string]any) map[string]interface{} {
	if in == nil {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
