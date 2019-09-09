package sqrlcrypto

import (
	"encoding/hex"
	"log"
	"testing"

	"github.com/smw1218/sqrlcrypto/identity_export"
)

func TestType1Encode(t *testing.T) {
	x := &S4Type1{
		Length:      125,
		Type:        1,
		PlainLength: 45,
		AESGCMIV:    [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		//ScryptSalt:                 make([]byte, 16),
		//EncryptedIdentityMasterKey: make([]byte, 32),
		//EncryptedIdentityLockKey:   make([]byte, 32),
		VerificationTag: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	encoded := x.Encode()
	if len(encoded) != 125 {
		t.Errorf("Wrong length: %v", len(encoded))
	}

	dec, err := S4Type1Decode(encoded)
	if err != nil {
		t.Errorf("Failed decode: %v", err)
	}

	if dec.AESGCMIV[0] != 1 {
		t.Errorf("Wrong value in byte array: %#v", dec.AESGCMIV)
	}
	if dec.VerificationTag[1] != 2 {
		t.Errorf("Wrong value in byte array: %#v", dec.VerificationTag)
	}
}

func TestSimpleExport(t *testing.T) {
	stored := identity_export.MustAsset("test1.sqrl")
	//stored := identity_export.MustAsset("simple_export.sqrl")
	decoded, err := S4Decode(stored)
	if err != nil {
		t.Fatalf("Error decoding: %v", err)
	}
	if decoded.MasterKey == nil {
		t.Errorf("MasterKey nil: %v", decoded)
	}
	if decoded.RescueCode == nil {
		t.Errorf("Rescue Code nil: %v", decoded)
	}

	mk := decoded.MasterKey
	log.Printf("Iterations: %d time: %d N: %d", mk.ScryptIterations, mk.PasswordVerifySeconds, mk.ScryptN)
	keyRes, err := EnScryptAgain(mk.ScryptSalt[:], "the password", int(mk.ScryptIterations), mk.ScryptN)
	//keyRes, err := EnScryptAgain(mk.ScryptSalt[:], "1q2w3e4", int(mk.ScryptIterations), mk.ScryptN)
	master, err := AESGCMDecrypt(keyRes.Value, append(mk.EncryptedIdentityMasterKey[:], mk.EncryptedIdentityLockKey[:]...), mk.AESGCMIV[:], mk.AdditionalData(), mk.VerificationTag[:])
	if err != nil {
		t.Errorf("Failed decrypt: %v", err)
	}

	if hex.EncodeToString(master) != "2970d2432dd6548d5d86843bb5f04fe47304cad0999c6315b07bec671090d7a9"+"f37c6817ee9c916a1efd4e648398b12372d5735f76db0984ece953e2be816a0f" {
		t.Errorf("Incorrect keys: %x", master)
	}

	rc := decoded.RescueCode
	keyResult, err := EnScryptAgain(rc.ScryptSalt[:], "894268272655451828340130", int(rc.ScryptIterations), rc.ScryptN)
	//keyResult, err := EnScryptAgain(rc.ScryptSalt[:], "154123679654974978215013", int(rc.ScryptIterations), rc.ScryptN)
	iuk, err := AESGCMDecrypt(keyResult.Value, rc.EncryptedIdentityUnlockKey[:], make([]byte, 12), rc.AdditionalData(), rc.VerificationTag[:])
	if err != nil {
		t.Errorf("Failed decrypt: %v", err)
	}
	if hex.EncodeToString(iuk) != "d8ef4bf9d7d8cd286ebd450ee2f4a7d222503fb1a27266b86a90bfcc0a4f99fa" {
		t.Errorf("Incorrect IUK: %x", iuk)
	}
}

func TestSimpleEncrypt(t *testing.T) {
	plain := []byte{0x29, 0x70, 0xd2, 0x43, 0x2d, 0xd6, 0x54, 0x8d, 0x5d, 0x86, 0x84, 0x3b, 0xb5, 0xf0, 0x4f, 0xe4, 0x73, 0x4, 0xca, 0xd0, 0x99, 0x9c, 0x63, 0x15, 0xb0, 0x7b, 0xec, 0x67, 0x10, 0x90, 0xd7, 0xa9, 0xf3, 0x7c, 0x68, 0x17, 0xee, 0x9c, 0x91, 0x6a, 0x1e, 0xfd, 0x4e, 0x64, 0x83, 0x98, 0xb1, 0x23, 0x72, 0xd5, 0x73, 0x5f, 0x76, 0xdb, 0x9, 0x84, 0xec, 0xe9, 0x53, 0xe2, 0xbe, 0x81, 0x6a, 0xf}
	stored := identity_export.MustAsset("test1.sqrl")
	//stored := identity_export.MustAsset("simple_export.sqrl")
	decoded, err := S4Decode(stored)
	if err != nil {
		t.Fatalf("Error decoding: %v", err)
	}
	if decoded.MasterKey == nil {
		t.Errorf("MasterKey nil: %v", decoded)
	}
	if decoded.RescueCode == nil {
		t.Errorf("Rescue Code nil: %v", decoded)
	}

	mk := decoded.MasterKey
	log.Printf("Iterations: %d time: %d N: %d", mk.ScryptIterations, mk.PasswordVerifySeconds, mk.ScryptN)
	keyRes, err := EnScryptAgain(mk.ScryptSalt[:], "the password", int(mk.ScryptIterations), mk.ScryptN)

	encrypted, err := AESGCMEncrypt(keyRes.Value, plain, mk.AESGCMIV[:], mk.AdditionalData())
	if err != nil {
		t.Fatalf("Err encryping: %v", err)
	}
	tagOffset := len(encrypted) - 16

	log.Printf("Enc body orig: %x tag %x", append(mk.EncryptedIdentityMasterKey[:], mk.EncryptedIdentityLockKey[:]...), mk.VerificationTag)
	log.Printf("Enc body mine: %x tag %x", encrypted[:tagOffset], encrypted[tagOffset:])
}
