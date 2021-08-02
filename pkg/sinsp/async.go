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

// RegisterAsyncExtractors is a helper function to be used within plugin_register_async_extractor.
//
// Intended usage as in the following example:
//
//     //export plugin_extract_str
//     func plugin_extract_str(pluginState unsafe.Pointer, evtnum uint64, id uint32, arg *byte, data *byte, datalen uint32) *C.char {
//     	...
//     }
//
//     //export plugin_register_async_extractor
//     func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
//     	return sinsp.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, plugin_extract_str)
//     }
//
func RegisterAsyncExtractors(
	pluginState unsafe.Pointer,
	asyncExtractorInfo unsafe.Pointer,
	strExtractorFunc PluginExtractStrFunc,
	u64ExtractorFunc PluginExtractU64Func,
) int32 {
	go func() {
		info := (*C.async_extractor_info)(asyncExtractorInfo)
		for C.wait_bridge(info) {
			(*info).rc = C.int32_t(ScapSuccess)
			switch uint32(info.ftype) {
			case ParamTypeCharBuf:
				if strExtractorFunc != nil {
					(*info).res_str = strExtractorFunc(
						pluginState,
						uint64(info.evtnum),
						(*byte)(unsafe.Pointer(info.field)),
						(*byte)(unsafe.Pointer(info.arg)),
						(*byte)(unsafe.Pointer(info.data)),
						uint32(info.datalen),
					)
				} else {
					(*info).rc = C.int32_t(ScapNotSupported)
				}
			case ParamTypeUint64:
				if u64ExtractorFunc != nil {
					var field_present uint32
					(*info).res_u64 = C.uint64_t(u64ExtractorFunc(
						pluginState,
						uint64(info.evtnum),
						(*byte)(unsafe.Pointer(info.field)),
						(*byte)(unsafe.Pointer(info.arg)),
						(*byte)(unsafe.Pointer(info.data)),
						uint32(info.datalen),
						&(field_present),
					))

					info.field_present = C.uint32_t(field_present)
				} else {
					(*info).rc = C.int32_t(ScapNotSupported)
				}
			default:
				(*info).rc = C.int32_t(ScapNotSupported)
			}
		}
	}()
	return ScapSuccess
}
