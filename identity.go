package sqrlcrypto

import (
	"crypto"
	"crypto/aes"
	"crypto/sha256"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/smw1218/sqrlcrypto/cipher"

	"github.com/aead/ecdh"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/scrypt"
)

type SqrlIdentity struct {
	IdentityUnlockKey []byte
	IdentityLockKey   []byte
	IdentityMasterKey []byte
	RescueCode        string
}

func (i *SqrlIdentity) IdentityUnlockAccessCode() []byte {
	return nil
}

type AEADEncrypted struct {
	Value []byte
	IV    []byte
	Tag   []byte
}

func AESGCMEncryptOld(rand io.Reader, password string, plaintext []byte, duration time.Duration) (*AEADEncrypted, error) {
	key, err := EnScrypt(rand, password, duration, 9)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand, iv); err != nil {
		return nil, err
	}

	dst, err := AESGCMEncrypt(key.Value, plaintext, iv)
	if err != nil {
		return nil, err
	}
	tagOffset := len(dst) - 16
	return &AEADEncrypted{
		Value: dst[:tagOffset],
		IV:    iv,
		Tag:   dst[tagOffset:],
	}, nil
}

func AESGCMEncrypt(key, plaintext, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesgcm.Seal(nil, iv, plaintext, nil), nil
}

func AESGCMDecrypt(key, encrypted, iv, tag []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCMWithTagSize(block, len(tag))
	if err != nil {
		return nil, err
	}
	concat := append(encrypted, tag...)
	log.Printf("concatsz: %v", len(concat))
	return aesgcm.Open(nil, iv, concat, nil)
}

func CreateIdentity(rand io.Reader, password string) (*SqrlIdentity, error) {
	identity := &SqrlIdentity{}

	dhka := ecdh.X25519()
	priv, pub, err := dhka.GenerateKey(rand)
	if err != nil {
		return nil, err
	}

	// IdentityUnlockKey is just random
	//identity.IdentityUnlockKey = make([]byte, 32)
	//_, err := io.ReadFull(rand, identity.IdentityUnlockKey)
	//if err != nil {
	//	return nil, err
	//}

	//dhka := ecdh.X25519()
	//identity.IdentityLockKey = dhka.PublicKey(identity.IdentityUnlockKey)
	//var pub [32]byte
	//curve25519.ScalarBaseMult(&pub, identity.IdentityUnlockKey)
	privbytes := priv.([32]byte)
	pubbytes := pub.([32]byte)
	identity.IdentityUnlockKey = privbytes[:]
	identity.IdentityLockKey = pubbytes[:]

	// IdentityMasterKey is the IUK EnHashed
	identity.IdentityMasterKey = EnHash(identity.IdentityUnlockKey)
	identity.RescueCode, err = RescueCode(rand)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func (si *SqrlIdentity) GenerateUnlockRequestSigningKey(serverUnlockKey []byte) ed25519.PrivateKey {
	dhka := ecdh.X25519()
	secret := dhka.ComputeSecret(si.IdentityUnlockKey, serverUnlockKey)
	return ed25519.NewKeyFromSeed(secret)
}

func (si *SqrlIdentity) GenerateUnlockPublicKeys(rand io.Reader) (suk crypto.PublicKey, vuk crypto.PublicKey, err error) {
	dhka := ecdh.X25519()
	randomUnlock, suk, err := dhka.GenerateKey(rand)
	if err != nil {
		return
	}

	secret := dhka.ComputeSecret(randomUnlock, si.IdentityLockKey)
	vuk = ed25519.NewKeyFromSeed(secret).Public()
	return
}

func EnHash(key []byte) []byte {
	// do first hash to make sure we end up with 256 bits
	result := sha256.Sum256(key)

	// spec says do this 16 times (minus the one above makes 15)
	for i := 0; i < 15; i++ {
		nextSha := sha256.Sum256(result[:])
		for j := 0; j < 32; j++ {
			result[j] ^= nextSha[j]
		}
	}
	return result[:]
}

type EnscryptResult struct {
	Value      []byte
	Salt       []byte
	Iterations int
	Duration   time.Duration
}

func EnScrypt(rand io.Reader, password string, duration time.Duration, logN byte) (*EnscryptResult, error) {
	er := &EnscryptResult{
		Iterations: 1,
	}
	er.Salt = make([]byte, 16)
	if _, err := io.ReadFull(rand, er.Salt); err != nil {
		return nil, err
	}

	start := time.Now()

	k, err := scrypt.Key([]byte(password), er.Salt, 1<<logN, 256, 1, 32)
	if err != nil {
		return nil, err
	}
	prevScrypt := k
	for time.Since(start) < duration {
		next, err := scrypt.Key([]byte(password), prevScrypt, 1<<logN, 256, 1, 32)
		if err != nil {
			return nil, err
		}
		for i := range k {
			k[i] ^= next[i]
		}
		prevScrypt = next
		er.Iterations++
	}
	er.Duration = time.Since(start)
	er.Value = k

	return er, nil
}

func EnScryptAgain(salt []byte, password string, iterations int, logN byte) (*EnscryptResult, error) {
	er := &EnscryptResult{
		Salt:       salt,
		Iterations: iterations,
	}

	start := time.Now()

	k, err := scrypt.Key([]byte(password), er.Salt, 1<<logN, 256, 1, 32)
	if err != nil {
		return nil, err
	}
	prevScrypt := k
	for it := 1; it < iterations; it++ {
		next, err := scrypt.Key([]byte(password), prevScrypt, 1<<logN, 256, 1, 32)
		if err != nil {
			return nil, err
		}
		for i := range k {
			k[i] ^= next[i]
		}
		prevScrypt = next
	}
	er.Duration = time.Since(start)
	er.Value = k

	return er, nil
}

// RescueCode is a 24 byte BCD value
func RescueCode(rand io.Reader) (string, error) {
	randBytes := make([]byte, 256)
	_, err := io.ReadFull(rand, randBytes)
	if err != nil {
		return "", err
	}

	bigInt := new(big.Int).SetBytes(randBytes)

	rescueCode := make([]byte, 24)
	ten := big.NewInt(10)
	for i := range rescueCode {
		_, mod := bigInt.DivMod(bigInt, ten, new(big.Int))
		rescueCode[i] = byte(mod.Int64()) + '0'
	}

	return string(rescueCode), nil
}
