package artifact

import (
	"sync"
	"time"

	sdktypes "github.com/chainreactors/sdk/pkg/types"
)

type statCollector struct {
	mu               sync.Mutex
	stats            []ExecutionStat
	onUpdate         func(latest ExecutionStat, count int)
	updateMinSpacing time.Duration
	lastUpdate       time.Time
}

func newStatCollector(onUpdate func(latest ExecutionStat, count int)) *statCollector {
	return &statCollector{
		onUpdate:         onUpdate,
		updateMinSpacing: 2 * time.Second,
	}
}

func (c *statCollector) Handler() func(sdktypes.Stats) {
	return func(stat sdktypes.Stats) {
		if c == nil {
			return
		}
		entry := ExecutionStat{
			Engine:     stat.Engine,
			Task:       stat.Task,
			Targets:    stat.Targets,
			Tasks:      stat.Tasks,
			Requests:   stat.Requests,
			Results:    stat.Results,
			Errors:     stat.Errors,
			DurationMs: stat.Duration.Milliseconds(),
		}

		var (
			cb    func(ExecutionStat, int)
			count int
		)
		now := time.Now()
		c.mu.Lock()
		c.stats = append(c.stats, entry)
		count = len(c.stats)
		if c.onUpdate != nil && (c.updateMinSpacing <= 0 || c.lastUpdate.IsZero() || now.Sub(c.lastUpdate) >= c.updateMinSpacing) {
			c.lastUpdate = now
			cb = c.onUpdate
		}
		c.mu.Unlock()
		if cb != nil {
			cb(entry, count)
		}
	}
}

func (c *statCollector) Stats() []ExecutionStat {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stats) == 0 {
		return nil
	}
	return append([]ExecutionStat(nil), c.stats...)
}

func (c *statCollector) Latest() (ExecutionStat, int, bool) {
	if c == nil {
		return ExecutionStat{}, 0, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.stats) == 0 {
		return ExecutionStat{}, 0, false
	}
	return c.stats[len(c.stats)-1], len(c.stats), true
}
