package jsonutil

import "encoding/json"

// Marshal encodes v as JSON. When pretty is true the output is indented.
func Marshal(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}
