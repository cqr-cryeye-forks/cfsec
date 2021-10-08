package formatters

import (
	"encoding/json"
	"io"

	"github.com/aquasecurity/defsec/rules"
)

type JSONOutput struct {
	Results []rules.FlatResult `json:"results"`
}

func FormatJSON(w io.Writer, results []rules.Result, _ string, options ...FormatterOption) error {
	var flattened []rules.FlatResult

	for _, result := range results {
		flattened = append(flattened, result.Flatten())
	}

	jsonWriter := json.NewEncoder(w)
	jsonWriter.SetIndent("", "\t")

	return jsonWriter.Encode(JSONOutput{flattened})
}