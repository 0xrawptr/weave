package workflow

import "testing"

func TestSplitCIDRToPrefix(t *testing.T) {
	tests := []struct {
		name   string
		target string
		prefix int
		want   int
	}{
		{name: "slash 20 to slash 24", target: "10.0.0.0/20", prefix: 24, want: 16},
		{name: "slash 23 to slash 24", target: "10.0.0.0/23", prefix: 24, want: 2},
		{name: "slash 24 stays one chunk", target: "10.0.0.0/24", prefix: 24, want: 1},
		{name: "slash 27 stays one chunk", target: "10.0.0.0/27", prefix: 24, want: 1},
		{name: "plain ip stays one chunk", target: "10.0.0.1", prefix: 24, want: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCIDRToPrefix(tt.target, tt.prefix)
			if len(got) != tt.want {
				t.Fatalf("len(splitCIDRToPrefix(%q, %d)) = %d, want %d: %#v", tt.target, tt.prefix, len(got), tt.want, got)
			}
		})
	}
}

func TestBuildPortScanChunksDeduplicates(t *testing.T) {
	chunks := buildPortScanChunks([]string{
		"10.0.0.0/23",
		"10.0.0.0/24",
		"10.0.2.1",
	}, 24)
	if len(chunks) != 3 {
		t.Fatalf("len(chunks) = %d, want 3: %#v", len(chunks), chunks)
	}
	if chunks[0].Chunk != "10.0.0.0/24" || chunks[1].Chunk != "10.0.1.0/24" || chunks[2].Chunk != "10.0.2.1" {
		t.Fatalf("unexpected chunks: %#v", chunks)
	}
}
