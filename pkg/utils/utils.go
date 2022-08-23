package utils

import (
	"encoding/json"
	"os"
	"unsafe"
)

func Getenv(key string, defaultValue string) string {
	val := os.Getenv(key)

	if len(val) == 0 {
		return defaultValue
	}

	return val
}

// StringToBytes converts string to byte slice without a memory allocation.
func StringToBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(
		&struct {
			string
			Cap int
		}{s, len(s)},
	))
}

// BytesToString converts byte slice to string without a memory allocation.
func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func DumpJSON[T any](data T) string {
	ret, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	return string(ret)
}
