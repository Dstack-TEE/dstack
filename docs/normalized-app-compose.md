# Normalized App Compose

In the dstack project, the `app-compose.json` file defines application composition and deployment settings. To track changes and ensure data integrity across different environments, dstack needs to generate a deterministic SHA256 compose hash from this file.

A compose hash is a SHA256 cryptographic hash computed from the `app-compose.json` content. This hash acts as a unique fingerprint for each application composition. When dstack processes the same `app-compose.json` file across different components - some built in Go, others in Python or JavaScript - they must all produce the exact same compose hash. This consistency is critical for dstack's distributed architecture and change detection system.

The main problem is that standard JSON libraries in different languages often create slightly different output from the same data. Small differences in key order, whitespace, or number formatting lead to different JSON strings. These create different compose hashes, which breaks dstack's integrity checks.

This document explains the rules for JSON serialization in Go, Python, and JavaScript to achieve deterministic output. Following these rules ensures the same `app-compose.json` file always produces the same SHA256 compose hash across all dstack components.

## Core Rules for Deterministic JSON

For dstack to generate consistent SHA256 compose hashes, JSON serialization must follow these strict rules:

- **Sort Keys**: All keys in JSON objects must be sorted alphabetically
- **Compact Output**: The JSON string must have no extra whitespace
- **Handle Special Values**: NaN and Infinity should be serialized as null
- **UTF-8 Encoding**: Non-ASCII characters should output directly as UTF-8, not as escape sequences

## Go: encoding/json

Go's standard library provides JSON encoding and decoding. By default, it creates compact output, but you need to watch key ordering and special value handling.

**Key Setup:**
- **Key Order**: Go serializes structs by field definition order. For `map[string]interface{}`, Go doesn't guarantee key order. To get sorted keys, convert to a map, extract and sort keys manually, then serialize. Better yet, use structs with fixed field order.
- **Compact Output**: `json.Marshal()` creates compact JSON by default
- **Special Values**: Go serializes NaN and Infinity to null by default
- **UTF-8**: Outputs UTF-8 characters by default

**Example (Go):**

```go
package main

import (
	"encoding/json"
	"fmt"
	"sort"
)

// AppComposeData represents the structure of app-compose.json
type AppComposeData struct {
	AStatus      bool                   `json:"a_status"`
	BNumber      int                    `json:"b_number"`
	ID           string                 `json:"id"`
	Nested       map[string]interface{} `json:"nested"`
	SpecialValue *float64               `json:"special_value"`
	Text         string                 `json:"text"`
	ZItems       []int                  `json:"z_items"`
}

// CustomMap for custom map serialization
type CustomMap map[string]interface{}

func (cm CustomMap) MarshalJSON() ([]byte, error) {
	keys := make([]string, 0, len(cm))
	for k := range cm {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Sort keys alphabetically

	var buf []byte
	buf = append(buf, '{')
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		keyBytes, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		buf = append(buf, keyBytes...)
		buf = append(buf, ':')
		valBytes, err := json.Marshal(cm[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, valBytes...)
	}
	buf = append(buf, '}')
	return buf, nil
}

func main() {
	// Example app-compose.json data
	nestedMap := CustomMap{
		"gamma": 3.14,
		"alpha": "first",
	}

	var nanVal *float64 = nil // Handle NaN as null

	composeData := AppComposeData{
		AStatus:      true,
		BNumber:      123,
		ID:           "c73a3a4e-ce71-4c12-a1b7-78be1a2e48e0",
		Nested:       nestedMap,
		SpecialValue: nanVal,
		Text:         "你好世界",
		ZItems:       []int{3, 1, 2},
	}

	// Generate deterministic JSON for compose hash
	jsonBytes, err := json.Marshal(composeData)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println("Deterministic JSON:", string(jsonBytes))
	
	// This JSON string can now be used to generate a compose hash
}
```

**Go Notes:**
- **Struct Field Order**: Go serializes structs by field definition order. Arrange struct fields alphabetically for consistency
- **Map Key Order**: Go doesn't guarantee map key order. Use custom `json.Marshaler` interface to sort keys manually
- **NaN/Infinity**: Go serializes these to null by default

## Python: json.dumps

Python's `json.dumps` has parameters to achieve deterministic output, but you must set them explicitly.

**Setup:**
- `sort_keys=True`: Sorts dictionary keys alphabetically
- `separators=(',', ':')`: Creates compact output by removing spaces
- `ensure_ascii=False`: Outputs non-ASCII characters as UTF-8
- `allow_nan=False`: Disables default NaN/Infinity serialization, handles them via custom function

**Example (Python):**

```python
import json
import math

def handle_nan_inf(obj):
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        return None  # Convert NaN, Inf, -Inf to None (serializes to null)
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

# Example app-compose.json data
compose_data = {
    "text": "你好世界",
    "id": "c73a3a4e-ce71-4c12-a1b7-78be1a2e48e0",
    "b_number": 123,
    "a_status": True,
    "z_items": [3, 1, 2],
    "nested": {
        "gamma": 3.14,
        "alpha": "first"
    },
    "special_value": float('nan')
}

# Generate deterministic JSON for compose hash
deterministic_json = json.dumps(
    compose_data,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
    default=handle_nan_inf
)

print("Deterministic JSON:", deterministic_json)
# This JSON string can now be used to generate a compose hash
```

## JavaScript: JSON.stringify

JavaScript's `JSON.stringify` is the hardest for deterministic output because it lacks a built-in sort keys option. Object key order is usually insertion order, but this isn't guaranteed to be alphabetical.

**Approach:**
- **Sort Object Keys**: Before calling `JSON.stringify`, recursively sort all object keys alphabetically
- **Compact Output**: Call `JSON.stringify` without the space argument
- **Special Values**: Use replacer function to convert NaN and Infinity to null

**Example (JavaScript):**

```javascript
/**
 * Sorts object keys alphabetically.
 * This is crucial for deterministic JSON.stringify in JavaScript.
 */
function sortObjectKeys(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(sortObjectKeys);
    }
    // Sort object keys and create new object
    return Object.keys(obj).sort().reduce((result, key) => {
        result[key] = sortObjectKeys(obj[key]);
        return result;
    }, {});
}

// Example app-compose.json data
const composeData = {
    text: "你好世界",
    id: "c73a3a4e-ce71-4c12-a1b7-78be1a2e48e0",
    b_number: 123,
    a_status: true,
    z_items: [3, 1, 2],
    nested: {
        gamma: 3.14,
        alpha: "first"
    },
    special_value: NaN
};

// Step 1: Sort object keys
const sortedData = sortObjectKeys(composeData);

// Step 2: Generate deterministic JSON for compose hash
const deterministicJson = JSON.stringify(sortedData, (key, value) => {
    // Convert NaN and Infinity to null
    if (typeof value === 'number' && (isNaN(value) || !isFinite(value))) {
        return null;
    }
    return value;
});

console.log("Deterministic JSON:", deterministicJson);
// This JSON string can now be used to generate a compose hash
```

## Language Comparison

Here's how each language handles deterministic JSON serialization for compose hash generation:

| Feature | Go encoding/json | Python json.dumps | JavaScript JSON.stringify |
|:---|:---|:---|:---|
| Key Order | Structs by definition order; maps need custom MarshalJSON | Not guaranteed; must set `sort_keys=True` | Not guaranteed; must sort keys manually |
| Whitespace | Compact by default | Has spaces by default; must set `separators=(',', ':')` | Has indentation by default; must omit space argument |
| NaN/Inf | Serializes to null by default | Defaults to JS equivalent; must set `allow_nan=False` | Serializes to null by default; use replacer function |
| Non-ASCII | Outputs UTF-8 by default | Defaults to escaped; must set `ensure_ascii=False` | Outputs UTF-8 by default |
| Custom Types | Use `json.Marshaler` interface | Use `default` parameter | Use replacer function |

## Summary

Getting deterministic JSON serialization across different languages for compose hash generation isn't the default behavior. It needs careful setup. Go works well with compact output and special value handling, but needs custom key sorting for maps. Python and JavaScript both need explicit setup for key sorting and compact output. JavaScript notably requires manual recursive sorting of object keys.

By following these recommendations, dstack can ensure that the same `app-compose.json` file produces the same SHA256 compose hash across all its Go, Python, and JavaScript components. This provides a reliable foundation for the project's distributed architecture and change detection system.

