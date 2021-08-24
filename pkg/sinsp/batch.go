package sinsp

import (
	"unsafe"
)

// NextFunc is the function type required by NextBatch().
type NextFunc func(plgState unsafe.Pointer, openState unsafe.Pointer) (*PluginEvent, int32)

// NextBatch is an helper function to be used within plugin_next_batch.
func NextBatch(plgState unsafe.Pointer, openState unsafe.Pointer, nextf NextFunc) ([]*PluginEvent, int32) {
	res := ScapSuccess

	evts := make([]*PluginEvent, 0)

	for len(evts) < MaxNextBatchEvents {
		var evt *PluginEvent
		evt, res = nextf(plgState, openState)
		if res == ScapSuccess {
			evts = append(evts, evt)
		} else {
			break
		}
	}

	return evts, res
}
