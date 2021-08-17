package main

// #cgo CFLAGS: -I${SRCDIR}/../../../libs/userspace/libscap
/*
#include <plugin_info.h>
*/
import "C"
import (
	"fmt"
	"log"
	"math/rand"
	"time"
	"unsafe"

	"github.com/mstemm/libsinsp-plugin-sdk-go/pkg/sinsp"
)

// Plugin consts
const (
	PluginRequiredApiVersion = "1.0.0"
	PluginID          uint32 = 111
	PluginName               = "batch"
	PluginDescription        = "do almost nothing"
	PluginContact            = "github.com/leogr/plugins/"
	PluginVersion     string = "0.0.1"
	PluginEventSource        = "fake_batch_events"
)

const nextBufSize uint32 = 65535
const outBufSize uint32 = 4096

///////////////////////////////////////////////////////////////////////////////

type pluginCtx struct {
	m       map[int]string
	counter int
}

// todo: plugin_get_last_error() needs context as argument to avoid having this global
var gLastError error

//export plugin_get_type
func plugin_get_type() uint32 {
	log.Printf("[%s] plugin_get_type\n", PluginName)
	return sinsp.TypeSourcePlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", C.GoString(config))

	pState := sinsp.NewStateContainer()
	*rc = sinsp.ScapSuccess

	return pState
}

//export plugin_get_last_error
func plugin_get_last_error() *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PluginName)
	if gLastError != nil {
		return C.CString(gLastError.Error())
	}
	return nil
}

//export plugin_destroy
func plugin_destroy(pState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)
	sinsp.Free(pState)
}

//export plugin_get_id
func plugin_get_id() uint32 {
	log.Printf("[%s] plugin_get_id\n", PluginName)
	return PluginID
}

//export plugin_get_name
func plugin_get_name() *C.char {
	log.Printf("[%s] plugin_get_name\n", PluginName)
	return C.CString(PluginName)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	log.Printf("[%s] plugin_get_description\n", PluginName)
	return C.CString(PluginDescription)
}

//export plugin_get_contact
func plugin_get_contact() *C.char {
	log.Printf("[%s] plugin_get_contact\n", PluginName)
	return C.CString(PluginContact)
}

//export plugin_get_version
func plugin_get_version() *C.char {
	log.Printf("[%s] plugin_get_version\n", PluginName)
	return C.CString(PluginVersion)
}

//export plugin_get_event_source
func plugin_get_event_source() *C.char {
	log.Printf("[%s] plugin_get_event_source\n", PluginName)
	return C.CString(PluginEventSource)
}

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(PluginRequiredApiVersion)
}

// As this plugin is only to provide an example of how batch
// event handling works, it defines no fields.

//export plugin_open
func plugin_open(pState unsafe.Pointer, params *C.char, rc *int32) unsafe.Pointer {
	input := C.GoString(params)
	log.Printf("[%s] plugin_open, params: %s\n", PluginName, input)

	m := &pluginCtx{}
	m.m = make(map[int]string)
	m.m[4] = "ciao"

	oState := sinsp.NewStateContainer()
	sinsp.SetContext(oState, unsafe.Pointer(m))

	*rc = sinsp.ScapSuccess
	return oState
}

//export plugin_close
func plugin_close(pState unsafe.Pointer, oState unsafe.Pointer) {
	log.Printf("[%s] plugin_close\n", PluginName)
	m := (*pluginCtx)(sinsp.Context(oState))
	log.Printf("[%s] Dump context before freeing\n", PluginName)
	fmt.Println(m)
	sinsp.Free(oState)
}

// Next is the core event production function. It is called by both plugin_next() and plugin_next_batch()
func Next(pState unsafe.Pointer, oState unsafe.Pointer) (*sinsp.PluginEvent, int32) {

	m := (*pluginCtx)(sinsp.Context(oState))

	ret := sinsp.PluginEvent{}

	// dummy plugin always produce "dummy" data
	dummy := fmt.Sprintf("dummy%d", int(m.counter))
	m.counter++

	// Put something not usefull in Go memory
	m.m[rand.Intn(100)] = dummy

	ret.Data = []byte(dummy)
	ret.Timestamp = uint64(time.Now().UnixNano())

	return &ret, sinsp.ScapSuccess
}

//export plugin_next
func plugin_next(pState unsafe.Pointer, oState unsafe.Pointer, retEvt **C.ss_plugin_event) int32 {
	evt, res := Next(pState, oState)
	if res == sinsp.ScapSuccess {
		*retEvt = (*C.ss_plugin_event)(sinsp.Events([]*sinsp.PluginEvent{evt}))
	}

	log.Printf("[%s] plugin_next\n", PluginName)

	return res
}

//export plugin_event_to_string
func plugin_event_to_string(pState unsafe.Pointer, data *C.char, datalen uint32) *C.char {
	log.Printf("[%s] plugin_event_to_string\n", PluginName)
	// do something dummy with the string
	s := fmt.Sprintf("evt-to-string(len=%d): %s", datalen, C.GoStringN(data, C.int(datalen)))
	return C.CString(s)
}

//export plugin_next_batch
func plugin_next_batch(pState unsafe.Pointer, oState unsafe.Pointer, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
	evts, res := sinsp.NextBatch(pState, oState, Next)

	if res == sinsp.ScapSuccess {
		*retEvts = (*C.ss_plugin_event)(sinsp.Events(evts))
		*nevts = (uint32)(len(evts))
	}

	log.Printf("[%s] plugin_next_batch\n", PluginName)

	return res
}

func main() {}
