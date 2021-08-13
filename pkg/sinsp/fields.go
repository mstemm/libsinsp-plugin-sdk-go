package sinsp

// FieldEntry represents a single field entry that an extractor plugin can expose.
// Should be used when implementing plugin_get_fields().
type FieldEntry struct {
	Type               string `json:"type"`
	Name               string `json:"name"`
	ArgRequired        bool `json:"argRequired"`
	Display            string `json:"display"`
	Desc               string `json:"desc"`
	Properties         string `json:"properties"`
}
