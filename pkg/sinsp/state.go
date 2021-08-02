package sinsp

/*
#include <stdlib.h>
#include <stdint.h>
#include <plugin_info.h>

typedef struct {
   void* goMem;
} state;

void fill_event(ss_plugin_event *evts, int idx, uint8_t *data, uint32_t datalen, uint64_t ts)
{
   evts[idx].data = data;
   evts[idx].datalen = datalen;
   evts[idx].ts = ts;
}

*/
import "C"
import (
	"unsafe"
)

// NewStateContainer returns an opaque pointer to a memory container that
// may be safely passed back and forth to sinsp.
//
// A state container can reference a Go pointer (suitable for a Go context).
// Both are persisted in memory until manually freed.
// A state container must be manually freed by using Free().
// It can be either used as the state of a source plugin or an open state of the source plugin.
func NewStateContainer() unsafe.Pointer {
	pCtx := (*C.state)(C.malloc(C.sizeof_state))
	pCtx.goMem = nil
	return unsafe.Pointer(pCtx)
}

// SetContext sets the given reference ctx (a pointer to a Go allocated memory) into p,
// assuming p is a state container created with NewStateContainer().
//
// A previously set reference, if any, is removed from p, making it suitable for garbage collecting.
func SetContext(p unsafe.Pointer, ctx unsafe.Pointer) {
	state := (*C.state)(p)

	if state.goMem != nil {
		peristentPtrs.Delete(state.goMem)
	}

	state.goMem = ctx

	if ctx != nil {
		peristentPtrs.Store(ctx, ctx)
	}
}

// Context returns a pointer to Go allocated memory, if any, previously assigned into p with SetContext(),
// assuming p is a state container created with NewStateContainer().
func Context(p unsafe.Pointer) unsafe.Pointer {
	return (*C.state)(p).goMem
}

// Convert the provided slice of PluginEvents into a C array of
// ss_plugin_event structs, suitable for returning in
// plugin_next/plugin_next_batch.
//
// The return value is an unsafe.Pointer, as the C.ss_plugin_event
// type is package-specific and can't be easily used outside the
// package (See https://github.com/golang/go/issues/13467)

func Events(evts []*PluginEvent) unsafe.Pointer {
	ret := (*C.ss_plugin_event)(C.malloc((C.ulong)(len(evts))*C.sizeof_ss_plugin_event))
	for i, evt := range evts {
		C.fill_event(ret,
			(C.int)(i),
			(*C.uchar)(C.CBytes(evt.Data)),
			(C.uint)(len(evt.Data)),
			(C.ulong)(evt.Timestamp))
	}

	return (unsafe.Pointer)(ret)
}

// Free disposes of any C and Go memory assigned to p and finally free P,
// assuming p is a state container created with NewStateContainer().
func Free(p unsafe.Pointer) {
	SetContext(p, nil)
	C.free(p)
}
