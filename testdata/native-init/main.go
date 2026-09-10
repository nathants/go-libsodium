package main

// #cgo pkg-config: libsodium
// #include <sodium.h>
import "C"

import "github.com/nathants/go-libsodium"

func main() {
	if C.sodium_init() < 0 {
		panic("native initialization failed")
	}
	if C.sodium_init() != 1 {
		panic("native prior-initialization control did not return 1")
	}
	libsodium.Init()
	libsodium.Init()
	if _, err := libsodium.StreamKeygen(); err != nil {
		panic(err)
	}
}
