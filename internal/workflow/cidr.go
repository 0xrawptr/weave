package workflow

import (
	"net"

	"github.com/projectdiscovery/mapcidr"
)

const defaultCIDRChunkPrefix = 24

func splitCIDR(target string) []string {
	return splitCIDRToPrefix(target, defaultCIDRChunkPrefix)
}

func splitCIDRToPrefix(target string, prefix int) []string {
	_, ipnet, err := net.ParseCIDR(target)
	if err != nil {
		return []string{target}
	}
	mask, bits := ipnet.Mask.Size()
	if bits != 32 || prefix <= 0 || prefix > bits || mask > prefix {
		return []string{target}
	}
	if mask == prefix {
		return []string{ipnet.String()}
	}
	chunkCount := 1 << uint(prefix-mask)
	chunks, err := mapcidr.SplitIPNetIntoN(ipnet, chunkCount)
	if err != nil {
		return []string{target}
	}
	out := make([]string, len(chunks))
	for i, c := range chunks {
		out[i] = c.String()
	}
	return out
}

func workflowTargetIsCIDR(target string) bool {
	_, _, err := net.ParseCIDR(target)
	return err == nil
}

func workflowTargetIsIP(target string) bool {
	return net.ParseIP(target) != nil
}
