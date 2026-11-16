package protocol

import (
	"errors"
	"fmt"
	"slices"
)

type Version struct{ Major, Minor uint8 }

var (
	V4_1 = Version{4, 1}
)

const Name = "skid"

var Current = V4_1

var supported = []Version{V4_1}

func (version Version) String() string { return fmt.Sprintf("%d.%d", version.Major, version.Minor) }

func (version Version) Bytes() []byte { return []byte{version.Major, version.Minor} }

func Parse(b []byte) (Version, error) {
	if len(b) != 2 {
		return Version{}, fmt.Errorf("%w: expected 2 bytes, got %d", ErrBadVersion, len(b))
	}
	return Version{Major: b[0], Minor: b[1]}, nil
}

func (version Version) Check() error {
	if slices.Contains(supported, version) {
		return nil
	}
	return fmt.Errorf("%w: %s (supported: %v)", ErrUnsupportedVersion, version, supported)
}

func (version Version) Label(component string) string {
	return fmt.Sprintf("%s:v%d:%s", Name, version.Major, component)
}

var (
	ErrBadVersion         = errors.New("protocol: malformed version")
	ErrUnsupportedVersion = errors.New("protocol: unsupported version")
)
