package tlsboot

import "strings"

type BootstrapPolicy string

const (
	PolicyStrict    BootstrapPolicy = "strict"
	PolicyPragmatic BootstrapPolicy = "pragmatic"
)

func ParsePolicy(s string) BootstrapPolicy {
	switch BootstrapPolicy(strings.ToLower(strings.TrimSpace(s))) {
	case PolicyStrict:
		return PolicyStrict
	default:
		return PolicyPragmatic
	}
}
