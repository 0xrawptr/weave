package workflow

import "github.com/chainreactors/utils"

const defaultCIDRChunkPrefix = 24

func splitCIDR(target string) []string {
	return splitCIDRToPrefix(target, defaultCIDRChunkPrefix)
}

func splitCIDRToPrefix(target string, prefix int) []string {
	cidr := utils.ParseCIDR(target)
	if cidr == nil {
		return []string{target}
	}
	if prefix <= 0 || prefix > 32 || cidr.Mask > prefix {
		return []string{target}
	}
	chunks, err := cidr.Split(prefix)
	if err != nil {
		return []string{target}
	}
	out := make([]string, len(chunks))
	for i, c := range chunks {
		out[i] = c.String()
	}
	return out
}
