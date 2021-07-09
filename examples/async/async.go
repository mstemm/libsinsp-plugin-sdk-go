package main

import "C"
import (
	"encoding/json"
	"log"
	"unsafe"

	"github.com/mstemm/libsinsp-plugin-sdk-go/pkg/sinsp"
)

// Plugin consts
const (
	PluginApiVersion  string = "1.0.0"
	PluginVersion     string = "0.0.1"
	PluginName               = "async"
	PluginDescription        = "async extractor example"
	PluginContact            = "github.com/mstemm/libsinsp-plugin-sdk-go"
	PluginEventSources       = `["some-event-source"]`
)

///////////////////////////////////////////////////////////////////////////////

type pluginCtx struct {
	m       map[int]string
	counter int
}

// todo: plugin_get_last_error() needs context as argument to avoid having this global
var gLastError error

// export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(PluginApiVersion)
}

//export plugin_get_type
func plugin_get_type() uint32 {
	log.Printf("[%s] plugin_get_type\n", PluginName)
	return sinsp.TypeExtractorPlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", C.GoString(config))

	// This plugin does not need to set up any state, so do
	// nothing and return a nil pointer.

	*rc = sinsp.ScapSuccess

	return nil
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

//export plugin_get_extract_event_sources
func plugin_get_extract_event_sources() *C.char {
	log.Printf("[%s] plugin_get_extract_event_sources\n", PluginName)

	// Since this example defines an extract event sources
	// function, it should return a json array of event sources
	// from which this plugin can extract fields. We'll use the
	// made-up event source "some-event-source"

	return C.CString(PluginEventSources)
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PluginName)
	flds := []sinsp.FieldEntry{
		{Type: "string", Name: "async.field", Desc: "TBD"},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		gLastError = err
		return nil
	}

	return C.CString(string(b))
}

//export plugin_extract_str
func plugin_extract_str(pluginState unsafe.Pointer, evtnum uint64, field *byte, arg *byte, data *byte, datalen uint32) *C.char {
	//log.Printf("[%s] plugin_extract_str\n", PluginName)
	return C.CString("ciao")
}

//export plugin_extract_u64
func plugin_extract_u64(plgState unsafe.Pointer, evtnum uint64, field *byte, arg *byte, data *byte, datalen uint32, fieldPresent *uint32) uint64 {
	return 11
}

//export plugin_register_async_extractor
func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
	return sinsp.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, plugin_extract_str, plugin_extract_u64)
}

func main() {}
