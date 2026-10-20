package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

var (
	errDuplicateKey  = errors.New("a2a: duplicate JSON key")
	errDepthExceeded = errors.New("a2a: JSON depth exceeded")
	errTrailingJSON  = errors.New("a2a: trailing JSON value")
	errNotObject     = errors.New("a2a: top-level JSON must be an object")
)

// checkStrictJSON validates UTF-8, syntax, duplicate keys, depth and trailing
// data. It never retains field values, so it is safe for the L1 envelope path.
func checkStrictJSON(raw []byte, maxDepth int, requireObject bool) error {
	if len(raw) == 0 {
		return errors.New("a2a: empty JSON")
	}
	if !utf8.Valid(raw) {
		return errors.New("a2a: invalid UTF-8")
	}
	trimmed := bytes.TrimSpace(raw)
	if requireObject && (len(trimmed) == 0 || trimmed[0] != '{') {
		return errNotObject
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := walkJSON(dec, 0, maxDepth); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %v", errTrailingJSON, tok)
	}
	return nil
}

func walkJSON(dec *json.Decoder, depth, maxDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		if depth >= maxDepth {
			return errDepthExceeded
		}
		seen := make(map[string]struct{})
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyTok.(string)
			if !ok {
				return errors.New("a2a: object key is not a string")
			}
			if _, dup := seen[key]; dup {
				return fmt.Errorf("%w: %q", errDuplicateKey, key)
			}
			seen[key] = struct{}{}
			if err := walkJSON(dec, depth+1, maxDepth); err != nil {
				return err
			}
		}
		_, err = dec.Token() // closing '}'
		return err
	case '[':
		if depth >= maxDepth {
			return errDepthExceeded
		}
		for dec.More() {
			if err := walkJSON(dec, depth+1, maxDepth); err != nil {
				return err
			}
		}
		_, err = dec.Token() // closing ']'
		return err
	default:
		return fmt.Errorf("a2a: unexpected JSON delimiter %q", delim)
	}
}

// decodeStrictObject decodes a JSON object into dst after the structural
// checks. Unknown fields are rejected because the frozen v1.0 contract is
// closed-world for AgentCard and JSON-RPC envelopes.
func decodeStrictObject(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if tok, err := dec.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: %v", errTrailingJSON, tok)
	}
	return nil
}
