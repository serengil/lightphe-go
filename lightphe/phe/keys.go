package phe

import (
	"fmt"
	"strings"
)

// Key section names used in validation messages.
const (
	SectionPublic  = "public_key"
	SectionPrivate = "private_key"
)

// FieldPresence pairs a key field name with whether the caller supplied it.
type FieldPresence struct {
	Name    string
	Present bool
}

// Field is shorthand for building a FieldPresence.
func Field(name string, present bool) FieldPresence {
	return FieldPresence{Name: name, Present: present}
}

// RequireFields reports every missing field of a key section in one error, so
// that a caller fixing hand-written key material sees the whole list at once.
func RequireFields(alg Algorithm, section string, fields ...FieldPresence) error {
	var missing []string
	for _, f := range fields {
		if !f.Present {
			missing = append(missing, f.Name)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("lightphe: %s %q is missing required fields: [%s]: %w",
		alg, section, strings.Join(missing, " "), ErrInvalidKeys)
}

// RequireSection reports a missing key section, for example a keys object that
// carries a private key but no public key.
func RequireSection(alg Algorithm, section string) error {
	return fmt.Errorf("lightphe: %s keys must contain %q: %w", alg, section, ErrInvalidKeys)
}
