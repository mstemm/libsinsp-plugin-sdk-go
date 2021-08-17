package sinsp

// #cgo CFLAGS: -I${SRCDIR}/../../../libs/userspace/libscap
/*
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <plugin_info.h>

#include <unistd.h>

bool wait_bridge(async_extractor_info *info)
{
	return info->cb_wait(info->wait_ctx);
};
*/
import "C"
import (
	"unsafe"
)

// These helpers avoid duplicating the same conversion/iteration code in plugins
// that want to use the async extractor functions. It circuments the
// problems in https://github.com/golang/go/issues/13466.
//
// It also uses unsafe.Pointer so be careful with its use!

func WrapExtractFuncs(plgState unsafe.Pointer, evt unsafe.Pointer, numFields uint32, fields unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func) int32 {

	event := (*C.struct_ss_plugin_event)(evt)
	dataBuf := C.GoBytes(unsafe.Pointer(event.data), C.int(event.datalen))

	// https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
	flds := (*[1 << 28]C.struct_ss_plugin_extract_field)(unsafe.Pointer(fields))[:numFields:numFields]

	var i uint32
	for i = 0; i < numFields; i++ {
		fieldStr := C.GoString((*C.char)(flds[i].field))
		argStr := C.GoString((*C.char)(flds[i].arg))

		switch uint32(flds[i].ftype) {
		case ParamTypeCharBuf:
			present, str := strExtractorFunc(plgState, uint64(event.evtnum), dataBuf, uint64(event.ts), fieldStr, argStr)
			if present {
				flds[i].field_present = C.bool(true)
				flds[i].res_str = C.CString(str)
			} else {
				flds[i].field_present = C.bool(false)
				flds[i].res_str = nil
			}
		case ParamTypeUint64:
			present, u64 := u64ExtractorFunc(plgState, uint64(event.evtnum), dataBuf, uint64(event.ts), fieldStr, argStr)
			if present {
				flds[i].field_present = C.bool(true)
				flds[i].res_u64 = C.uint64_t(u64)
			} else {
				flds[i].field_present = C.bool(false)
			}
		}
	}

	return ScapSuccess
}

// RegisterAsyncExtractors is a helper function to be used within plugin_register_async_extractor/plugin_extract_fields.
//
// Intended usage as in the following example:
//
//     // A function to extract a single string field from an event
//     func extract_str(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
//     	...
//     }
//
//     // A function to extract a single uint64 field from an event
//     func extract_u64(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
//      ...
//     }
//
//     //export plugin_extract_fields
//     func plugin_extract_fields(plgState unsafe.Pointer, evt *C.struct_ss_plugin_event, field *C.struct_ss_plugin_extract_field) uint32 {
//       return sinsp.WrapExtractFuncs(plgState, unsafe.Pointer(evt), unsafe.Pointer(field), extract_str, extract_u64)
//     }
//
//     //export plugin_register_async_extractor
//     func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
//     	return sinsp.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, plugin_extract_str)
//     }
//
//
// If https://github.com/golang/go/issues/13467 were fixed,
//  RegisterAsyncExtractors could directly use the C functions (and their C
// types) used by the API. Since we can't, we use go native types
// instead and change their return values to be more golang-friendly.

func RegisterAsyncExtractors(
	pluginState unsafe.Pointer,
	asyncExtractorInfo unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func,
) int32 {
	go func() {
		info := (*C.async_extractor_info)(asyncExtractorInfo)
		for C.wait_bridge(info) {
			info.rc = C.int32_t(ScapSuccess)

			dataBuf := C.GoBytes(unsafe.Pointer(info.evt.data), C.int(info.evt.datalen))

			fieldStr := C.GoString((*C.char)(info.field.field))
			argStr := C.GoString((*C.char)(info.field.arg))

			switch uint32(info.field.ftype) {
			case ParamTypeCharBuf:
				if strExtractorFunc != nil {
					present, str := strExtractorFunc(pluginState, uint64(info.evt.evtnum), dataBuf, uint64(info.evt.ts), fieldStr, argStr)

					if present {
						info.field.field_present = C.bool(true)
						info.field.res_str = C.CString(str)
					} else {
						info.field.field_present = C.bool(false)
						info.field.res_str = nil
					}
				} else {
					info.rc = C.int32_t(ScapNotSupported)
				}
			case ParamTypeUint64:
				if u64ExtractorFunc != nil {
					present, u64 := u64ExtractorFunc(pluginState, uint64(info.evt.evtnum), dataBuf, uint64(info.evt.ts), fieldStr, argStr)

					if (!present){
						info.field.field_present = C.bool(true)
					} else {
						info.field.field_present = C.bool(false)
						info.field.res_u64 = C.uint64_t(u64)
					}
				} else {
					info.rc = C.int32_t(ScapNotSupported)
				}
			default:
				info.rc = C.int32_t(ScapNotSupported)
			}
		}
	}()
	return ScapSuccess
}
