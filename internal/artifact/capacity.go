package artifact

import sdktypes "github.com/chainreactors/sdk/pkg/types"

// SDKCapacityResizable is implemented by artifacts backed by an SDK engine
// with a local capacity bucket.
type SDKCapacityResizable interface {
	ResizeSDKCapacity(schedulerSlots int) int
	SDKCapacityTotal() int
}

func resizeSDKCapacity(capacity interface {
	Capacity() *sdktypes.Capacity
	SetCapacity(int)
}, total int) int {
	if total <= 0 {
		return 0
	}
	bucket := capacity.Capacity()
	if bucket == nil {
		capacity.SetCapacity(total)
		return total
	}
	bucket.Resize(total)
	return bucket.Total()
}
