package main

import "C"
import (
	"unsafe"
	"github.com/handsomecheung/mb64"
)

//export SetEncodingC
func SetEncodingC(key *C.char) C.int {
	goKey := C.GoString(key)
	err := mb64.SetEncoding(goKey)
	if err != nil {
		return -1
	}
	return 0
}

//export BypassC
func BypassC() {
	mb64.Bypass()
}

//export EncodeC
func EncodeC(data *C.char, dataLen C.int, result **C.char, resultLen *C.int) C.int {
	goData := C.GoBytes(unsafe.Pointer(data), dataLen)
	encoded, err := mb64.Encode(goData)
	if err != nil {
		return -1
	}

	*result = C.CString(string(encoded))
	*resultLen = C.int(len(encoded))
	return 0
}

//export DecodeC
func DecodeC(data *C.char, dataLen C.int, result **C.char, resultLen *C.int) C.int {
	goData := C.GoBytes(unsafe.Pointer(data), dataLen)
	decoded, err := mb64.Decode(goData)
	if err != nil {
		return -1
	}

	*result = C.CString(string(decoded))
	*resultLen = C.int(len(decoded))
	return 0
}

//export FreeC
func FreeC(ptr *C.char) {
	// Memory allocated by C.CString should be freed by caller
}

func main() {}
