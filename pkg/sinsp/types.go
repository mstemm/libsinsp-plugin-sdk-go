package sinsp

import "unsafe"

// PluginExtractStrFunc/PluginExtractU64Func are used when setting up
// an async extractor via RegisterAsyncExtractors.
//
// If https://github.com/golang/go/issues/13467 were fixed, this
// function signature could directly use the C functions (and their C
// types) used by the API. Since we can't, we use go native types
// instead and change their return values to be more golang-friendly.
//
// The return value should be (field present as bool, extracted value)
type PluginExtractStrFunc func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string)
type PluginExtractU64Func func(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64)

type PluginEvent struct {
	Evtnum         uint64
	Data           []byte
	Timestamp      uint64
}
