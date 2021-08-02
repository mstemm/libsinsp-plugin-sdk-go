package main

/*
#include <stdlib.h>
#include <stdint.h>
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
	PluginID          uint32 = 111
	PluginName               = "dummy"
	PluginDescription        = "do almost nothing"
	PluginContact            = "github.com/mstemm/libsinsp-plugin-sdk-go"
	PluginVersion            = "1.0.0"
	PluginEventSource        = "dummy_event"
)

///////////////////////////////////////////////////////////////////////////////

type pluginInstance struct {
	// This reflects potential internal state for the plugin
	m       map[int]string

	// This tracks the number of events returned via next()
	counter int
}

// todo: plugin_get_last_error() needs context as argument to avoid having this global
var gLastError error

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
	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", C.GoString(config))

	pState := sinsp.NewStateContainer()
	*rc = sinsp.ScapSuccess

	return pState
}

//export plugin_destroy
func plugin_destroy(pState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)
}

//export plugin_get_last_error
func plugin_get_last_error() *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PluginName)
	if gLastError != nil {
		return C.CString(gLastError.Error())
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
	return C.CString(PluginEventSource)
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PluginName)
	flds := []sinsp.FieldEntry{
		{Type: "uint64", Name: "dummy.count", Desc: "TBD"},
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
	input := C.GoString(params)
	log.Printf("[%s] plugin_open, params: %s\n", PluginName, input)

	m := &pluginInstance{
		m:           make(map[int]string),
		counter:     0,
	}
	m.m[4] = "ciao"

	oState := sinsp.NewStateContainer()
	sinsp.SetContext(oState, unsafe.Pointer(m))

	*rc = sinsp.ScapSuccess
	return oState
}

//export plugin_close
func plugin_close(pState unsafe.Pointer, oState unsafe.Pointer) {
	log.Printf("[%s] plugin_close\n", PluginName)
	m := (*pluginInstance)(sinsp.Context(oState))
	log.Printf("[%s] Dump context before freeing\n", PluginName)
	fmt.Println(m)
	sinsp.Free(oState)
}

//export plugin_next
func plugin_next(pState unsafe.Pointer, oState unsafe.Pointer, retEvt *unsafe.Pointer) int32 {
	log.Printf("[%s] plugin_next\n", PluginName)

	// time.Sleep(time.Second)

	m := (*pluginInstance)(sinsp.Context(oState))

	// dummy plugin always produce "dummy" data
	dummy := fmt.Sprintf("dummy%d", int(m.counter))
	m.counter++

	// Update some internal state
	m.m[rand.Intn(100)] = dummy

	evt := &sinsp.PluginEvent{
		Data:              []byte(dummy),
		Timestamp:         uint64(time.Now().Unix()) * 1000000000,
	}

	*retEvt = sinsp.Events([]*sinsp.PluginEvent{evt})

	return sinsp.ScapSuccess
}

//export plugin_event_to_string
func plugin_event_to_string(plgState unsafe.Pointer, data *C.char, datalen uint32) *C.char {
	log.Printf("[%s] plugin_event_to_string %v\n", PluginName, C.GoStringN(data, C.int(datalen)))
	// do something dummy with the string
	s := fmt.Sprintf("evt-to-string(len=%d): %s", datalen, C.GoStringN(data, C.int(datalen)))
	return C.CString(s)
}

func main() {}
