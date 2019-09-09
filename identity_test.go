package sqrlcrypto

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
	"time"
)

func TestRescueCode(t *testing.T) {
	rc, err := RescueCode(rand.Reader)
	if err != nil {
		t.Errorf("Error making resuce code: %v", err)
	}
	for _, b := range rc {
		if b > 9+'0' || b < '0' {
			t.Errorf("Invalid value %v", b)
		}
	}
}

func TestEnscrypt(t *testing.T) {
	res, err := EnScrypt(rand.Reader, "somepassword", 100*time.Millisecond, 9)
	if err != nil {
		t.Fatalf("Failed EnScrypt: %v", err)
	}
	if res.Duration < 100*time.Millisecond {
		t.Errorf("Didn't meet time: %#v", res)
	}

	res2, err := EnScryptAgain(res.Salt, "somepassword", res.Iterations, 9)
	if err != nil {
		t.Fatalf("Failed EnScryptAgain: %v", err)
	}
	if string(res2.Value) != string(res.Value) {
		t.Errorf("Values not equal first: %v again: %v", res.Value, res2.Value)
	}
}
func TestEnscryptStaticSingle(t *testing.T) {
	salt := []byte{}
	res, err := EnScryptAgain(salt, "", 1, 9)
	if err != nil {
		t.Fatalf("Failed EnScryptAgain: %v", err)
	}
	hexValue := hex.EncodeToString(res.Value)
	if hexValue != "a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c" {
		t.Errorf("Values not equal first: %v again: a8ea62a6e1bfd20e4275011595307aa302645c1801600ef5cd79bf9d884d911c", hexValue)
	}
}

func TestEnscryptStaticMany(t *testing.T) {
	salt := make([]byte, 32)
	res, err := EnScryptAgain(salt, "password", 123, 9)
	if err != nil {
		t.Fatalf("Failed EnScryptAgain: %v", err)
	}
	hexValue := hex.EncodeToString(res.Value)
	if hexValue != "2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d" {
		t.Errorf("Values not equal first: %v again: 2f30b9d4e5c48056177ff90a6cc9da04b648a7e8451dfa60da56c148187f6a7d", hexValue)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	res, err := EnScrypt(rand.Reader, "somepassword", 100*time.Millisecond, 9)
	if err != nil {
		t.Fatalf("Failed EnScrypt: %v", err)
	}

	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)

	enc, err := AESGCMEncrypt(res.Value, []byte("supersecretstuff"), iv, nil)
	if err != nil {
		t.Errorf("Failed encrypt: %v", err)
	}
	tagOffset := len(enc) - 16

	master, err := AESGCMDecrypt(res.Value, enc[:tagOffset], iv, nil, enc[tagOffset:])
	if err != nil {
		t.Errorf("Failed decrypt: %v", err)
	}
	if string(master) != "supersecretstuff" {
		t.Errorf("Wrong value: %v", string(master))
	}
}
