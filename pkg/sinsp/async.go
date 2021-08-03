package sinsp

// #cgo CFLAGS: -I${SRCDIR}/../../../libs/userspace/libscap
/*
#include <stdlib.h>
#include <stdint.h>

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

// These helpers avoid duplicating the same conversion code in plugins
// that want to use the async extractor functions. It circuments the
// problems in https://github.com/golang/go/issues/13466.
//
// It also uses unsafe.Pointer so be careful with its use!

func WrapExtractStr(plgState unsafe.Pointer, evtnum uint64, field unsafe.Pointer, arg unsafe.Pointer, data unsafe.Pointer, datalen uint32, strExtractorFunc PluginExtractStrFunc) unsafe.Pointer {
	fieldStr := C.GoString((*C.char)(field))
	argStr := C.GoString((*C.char)(arg))
	dataBuf := C.GoBytes(data, C.int(datalen))

	present, extractStr := strExtractorFunc(plgState, evtnum, fieldStr, argStr, dataBuf)

	if (!present) {
		return nil
	}

	return unsafe.Pointer(C.CString(extractStr))
}

func WrapExtractU64(plgState unsafe.Pointer, evtnum uint64, field unsafe.Pointer, arg unsafe.Pointer, data unsafe.Pointer, datalen uint32, fieldPresent *uint32, u64ExtractorFunc PluginExtractU64Func) uint64 {
	fieldStr := C.GoString((*C.char)(field))
	argStr := C.GoString((*C.char)(arg))
	dataBuf := C.GoBytes(data, C.int(datalen))

	present, extractU64 := u64ExtractorFunc(plgState, evtnum, fieldStr, argStr, dataBuf)

	if (!present) {
		*fieldPresent = 0
		return 0
	}

	*fieldPresent = 1
	return extractU64
}

// RegisterAsyncExtractors is a helper function to be used within plugin_register_async_extractor.
//
// Intended usage as in the following example:
//
//     // A function called by plugin_extract_str after conversion from C types to go types
//     func extract_str(pluginState unsafe.Pointer, evtnum uint64, field string, arg string, data []byte) (bool, string) {
//     	...
//     }
//
//     // A function called by plugin_extract_u64 after conversion from C types to go types
//     func extract_u64(pluginState unsafe.Pointer, evtnum uint64, field string, arg string, data []byte) (bool, uint64) {
//      ...
//     }
//
//     //export plugin_extract_str
//     func plugin_extract_str(plgState unsafe.Pointer, evtnum uint64, field *C.char, arg *C.char, data *C.uint8_t, datalen uint32) *C.char {
//      // A plugin can also do their own conversion, but this wrapper handles the conversion automatically.
//	return (*C.char)(sinsp.WrapExtractStr(plgState, evtnum, unsafe.Pointer(field), unsafe.Pointer(arg), unsafe.Pointer(data), datalen, extract_str))
//     }
//
//     //export plugin_extract_u64
//     func plugin_extract_u64(plgState unsafe.Pointer, evtnum uint64, field *C.char, arg *C.char, data *C.uint8_t, datalen uint32, fieldPresent *uint32) uint64 {
//	return sinsp.WrapExtractU64(plgState, evtnum, unsafe.Pointer(field), unsafe.Pointer(arg), unsafe.Pointer(data), datalen, fieldPresent, extract_u64)
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

			fieldStr := C.GoString((*C.char)(unsafe.Pointer(info.field)))
			argStr := C.GoString((*C.char)(unsafe.Pointer(info.arg)))
			dataBuf := C.GoBytes(unsafe.Pointer(info.data), C.int(info.datalen))

			switch uint32(info.ftype) {
			case ParamTypeCharBuf:
				if strExtractorFunc != nil {
					present, extractStr := strExtractorFunc(pluginState, uint64(info.evtnum), fieldStr, argStr, dataBuf)

					if (!present){
						info.field_present = C.uint32_t(0)
						info.res_str = nil
					} else {
						info.field_present = C.uint32_t(1)
						info.res_str = C.CString(extractStr)
					}
				} else {
					info.rc = C.int32_t(ScapNotSupported)
				}
			case ParamTypeUint64:
				if u64ExtractorFunc != nil {
					present, extractU64 := u64ExtractorFunc(pluginState, uint64(info.evtnum), fieldStr, argStr, dataBuf)

					if (!present){
						info.field_present = 0
					} else {
						info.field_present = 1
					}
					info.res_u64 = C.uint64_t(extractU64)
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
