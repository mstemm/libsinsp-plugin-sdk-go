package main

// #cgo CFLAGS: -I${SRCDIR}/../../../libs/userspace/libscap
/*
#include <plugin_info.h>
*/
import "C"
import (
	"encoding/json"
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
	PluginID          uint32 = 3
	PluginName               = "dummy"
	PluginDescription        = "Reference plugin for educational purposes"
	PluginContact            = "github.com/mstemm/libsinsp-plugin-sdk-go"
	PluginVersion            = "1.0.0"
	PluginEventSource        = "dummy"
)

///////////////////////////////////////////////////////////////////////////////

type pluginEventBuf struct {
	sample             uint64   `json:"sample"`
	sampleHistory      string   `json:"history"`
}

type pluginState struct {

	// A copy of the config provided to plugin_init()
	config string

	// When a function results in an erorr, this is set and can be
	// retrieved in plugin_get_last_error().
	lastError error

	// This reflects potential internal state for the plugin
	jitter uint64

	// Will be used to randomize samples
	rand *rand.Rand

	instanceStates []*instanceState
}

type instanceState struct {

	// Copy of the init params from plugin_open()
	initParams string

	// The number of events to return before EOF
	maxEvents uint64

	// A count of events returned. This is put in every event as
	// the evtnum property.
	counter int

	// A semi-random numeric value, derived from the counter and
	// jitter. This is put in every event as the data property.
	sample uint64

	// This string contains the last 10 transitions of the sample
	// from its prior value, encoded as '+' or '-' characters. If
	// the sample increased from its prior value, this is
	// represented by a '+'. Similarly, if the sample decreased
	// this is represented by a '-' if the sample decreased.
	sampleHistory string
}

var pluginStates []*pluginState = []*pluginState{}

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(PluginRequiredApiVersion)
}

//export plugin_get_type
func plugin_get_type() uint32 {
	log.Printf("[%s] plugin_get_type\n", PluginName)
	return sinsp.TypeSourcePlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	cfg := C.GoString(config)
	log.Printf("[%s] plugin_init config=%s\n", PluginName, cfg)

	// The format of cfg is a json object with a single param
	// "jitter", e.g. {"jitter": 10}
	obj := map[string]uint64
	err := json.Unmarshal(byte[](cfg), &obj)
	if err != nil {
		return nil
	}
	if _, ok := obj["jitter"]; !ok {
		return nil
	}

	ps := &pluginState{
		config:           cfg,
		lastError:        nil,
		jitter:           obj["jitter"],
		rand:             rand.New(time.Now().UnixNano()),
		instanceStates:   make([]*instanceState, 0),
	}

	// Adding to this package-level slice ensures the struct will
	// not be garbage collected
	pluginStates := append(pluginStates, ps)

	*rc = sinsp.ScapSuccess

	return unsafe.Pointer(ps)
}

//export plugin_destroy
func plugin_destroy(pState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)

	ps := (*pluginState)(pState)

	for i, p := range pluginStates {
		if p == ps {
			pluginStates[i] = pluginStates[len(pluginStates)-1]
			pluginStates = pluginStates[:len(pluginStates)-1]
			return
		}
	}
}

//export plugin_get_last_error
func plugin_get_last_error(pState unsafe.Pointer) *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PluginName)

	ps := (*pluginState)(pState)

	if ps.lastError != nil {
		return C.CString(ps.lastError.Error())
	}
	return nil
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

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PluginName)

	flds := []sinsp.FieldEntry{
		{Type: "string", Name: "dummy.sampleHistory", Desc: "The last 10 transitions of the sample from its prior value, encoded as '+' or '-'"},
		{Type: "string", Name: "dummy.sampleHistoryAt", ArgRequired: true, Desc: "Indexes 0-9 into the transitions from sampleHistory"},
		{Type: "uint64", Name: "dummy.value", Desc: "The sample value in the event"},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		gLastError = err
		return nil
	}

	return C.CString(string(b))
}

//export plugin_open
func plugin_open(pState unsafe.Pointer, params *C.char, rc *int32) unsafe.Pointer {
	prms := C.GoString(params)
	log.Printf("[%s] plugin_open, params: %s\n", PluginName, prms)

	ps := (*pluginState)(pState)

	// The format of params is a json object with two params:
	// - "start", which denotes the initial value of sample
	// - "maxEvents": which denotes the number of events to return before EOF.
	// Example:
	// {"start": 1, "maxEvents": 1000}
	obj := map[string]uint64
	err := json.Unmarshal(byte[](cfg), &obj)
	if err != nil {
		ps.err = fmt.Errorf("Params %s could not be parsed: %v", prms, err)
		return nil
	}
	if _, ok := obj["start"]; !ok {
		ps.err = fmt.Errorf("Params %s did not contain start property", prms)
		return nil
	}

	is := &instanceState{
		initParams:       prms,
		counter:          0,
		sample:           obj["start"],
		sampleHistory:    make([]string, 0),
	}

	ps.instanceStates = append(plugin.instanceStates, is)

	*rc = sinsp.ScapSuccess
	return unsafe.Pointer(os)
}

//export plugin_close
func plugin_close(pState unsafe.Pointer, iState unsafe.Pointer) {
	log.Printf("[%s] plugin_close\n", PluginName)

	ps := (*pluginState)(pState)
	is := (*instanceState)(iState)

	for i, istate := range ps {
		if istate == is {
			ps.instanceStates[i] = ps.instanceStates[len(ps.instanceStates)-1]
			ps.instanceStates = ps.instanceStates[:len(ps.instanceStates)-1]
			return
		}
	}
}

//export plugin_next
func plugin_next(pState unsafe.Pointer, iState unsafe.Pointer, retEvt **C.ss_plugin_event) int32 {
	log.Printf("[%s] plugin_next\n", PluginName)

	ps := (*pluginState)(pState)
	is := (*instanceState)(iState)

	// The representation of a dummy event is a json string with
	// the current sample value and sample history. Although the
	// sample history is also maintained in the instance state,
	// the instance state is *not* provided to
	// plugin_extract_fields, only the event, so it must be
	// encoded in the event.

	is.counter++
	lastSample := is.sample

	// Increment sample regardless
	is.sample++

	// Also add a jitter of [-jitter:+jitter], lower bounding at zero
	bump := ps.rand.Int31n(is.jitter+1)
	dir := ps.rand.Int()
	if dir % 2 == 0 {
		is.sampleHistory = append(is.sampleHistory, "+")
		// Increase by bump
		is.sample += bump
	} else {
		is.sampleHistory = append(is.sampleHistory, "-")
		// Decrease by bump, but not less than 0
		if is.sample < bump {
			is.sample = 0
		} else {
			is.sample -= bump
		}
	}

	// Truncate sample history if needed
	while len(is.sampleHistory) > 10 {
		is.sampleHistory = is.sampleHistory[:10]
	}

	hist := ""
	for i, val := range is.sampleHistory {
		hist += val
	}

	buf := &pluginEventBuf{
		sample:          is.sample,
		sampleHistory:   hist,
	}

	b, err := json.Marshal(buf)
	if err != nil {
		ps.lastError = fmt.Errorf("Could not marshal event: %v", err)
		return sinsp.ScapFailure
	}

	// It is not mandatory to set the Timestamp of the event (it
	// would be filled in by the framework if set to uint_max),
	// but it's a good practice.
	evt := &sinsp.PluginEvent{
		Evtnum:            is.counter,
		Data:              []byte(b),
		Timestamp:         uint64(time.Now().Unix()) * 1000000000,
	}

	// This function takes care of the conversion from the go
	// struct to the C ss_plugin_event struct.
	*retEvt = (*C.ss_plugin_event)(sinsp.Events([]*sinsp.PluginEvent{evt}))

	return sinsp.ScapSuccess
}

//export plugin_event_to_string
func plugin_event_to_string(plgState unsafe.Pointer, data *C.uint8_t, datalen uint32) *C.char {

	// This can blindly convert the C.uint8_t to a *C.char, as the
	// plugin always returns a C string as the event buffer.
	evtStr := C.GoStringN((*C.char)(unsafe.Pointer(data)), C.int(datalen))

	log.Printf("[%s] plugin_event_to_string %v\n", PluginName, evtStr)
	// do something dummy with the string
	s := fmt.Sprintf("evt-to-string(len=%d): %s", datalen, evtStr)
	return C.CString(s)
}

func main() {}
