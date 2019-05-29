package dpapi

import (
	"encoding/binary"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// some API constants
const (
	CRYPTPROTECT_UI_FORBIDDEN = 0x1
)

var (
	dllcrypt32  = syscall.NewLazyDLL("Crypt32.dll")
	dllkernel32 = syscall.NewLazyDLL("Kernel32.dll")

	procEncryptData = dllcrypt32.NewProc("CryptProtectData")
	procDecryptData = dllcrypt32.NewProc("CryptUnprotectData")
	procLocalFree   = dllkernel32.NewProc("LocalFree")
)

// DATA_BLOB  is a structure used by Windows DPAPI Crypt32.dll::CryptProtectData(DATA_BLOB...)
type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

// NewBlob creates DATA_BLOB and fills member pbData
func NewBlob(d []byte) *DATA_BLOB {
	if len(d) == 0 {
		return &DATA_BLOB{}
	}
	return &DATA_BLOB{
		pbData: &d[0],
		cbData: uint32(len(d)),
	}
}

// ToByteArray creates []byte from *byte member
func (b *DATA_BLOB) ToByteArray() []byte {
	d := make([]byte, b.cbData)
	copy(d, (*[1 << 30]byte)(unsafe.Pointer(b.pbData))[:])
	return d
}

// Encrypt calls DPAPI CryptProtectData
func Encrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procEncryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	// outblob.pbData allocated inside LSA and must be freed by us
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

// Decrypt calls Crypt32.dll::CryptUnprotectData
func Decrypt(data []byte) ([]byte, error) {
	var outblob DATA_BLOB
	r, _, err := procDecryptData.Call(uintptr(unsafe.Pointer(NewBlob(data))), 0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&outblob)))
	if r == 0 {
		return nil, err
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outblob.pbData)))
	return outblob.ToByteArray(), nil
}

// ConvertToUTF16LittleEndianBytes , Windows is Little endian.
func ConvertToUTF16LittleEndianBytes(s string) []byte {
	u := utf16.Encode([]rune(s)) // encode in UTF16
	b := make([]byte, 2*len(u))
	for index, value := range u {
		binary.LittleEndian.PutUint16(b[index*2:], value) // change to LittleEndian
	}
	return b
}

// Usage
// const secret = "MYpasswd"
// // or s := convertToUTF16LittleEndianBytes(secret)
// enc, err := Encrypt([]byte(secret))
// if err != nil {
//     log.Fatalf("Encrypt failed: %v", err)
// }
// dec, err := Decrypt(enc)
// if err != nil {
//     log.Fatalf("Decrypt failed: %v", err)
// }
