package crypto

import "github.com/slipe-fun/skid-v4/pkg/protocol"

func BuildAAD(aadType string, version protocol.Version, fields ...[]byte) []byte {
	contextTag := []byte(version.Label(aadType))

	allFields := make([][]byte, 0, len(fields)+1)
	allFields = append(allFields, contextTag)
	allFields = append(allFields, fields...)

	return ConcatBytes(allFields...)
}
