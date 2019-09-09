package sqrlcrypto

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"log"
)

func S4Decode(data []byte) (*S4Data, error) {
	dataOffset := 8
	if string(data[0:8]) == "SQRLDATA" {
		tmpdata := make([]byte, base64.RawURLEncoding.DecodedLen(len(data[8:])))
		_, err := base64.RawURLEncoding.Decode(tmpdata, data[8:])
		if err != nil {
			return nil, err
		}
		data = tmpdata
		dataOffset = 0
	} else if string(data[0:8]) != "sqrldata" {
		return nil, fmt.Errorf("Invalid S4 identity")
	}

	s4data := &S4Data{}
	var err error

	for dataOffset < len(data) {
		length, blockType := peekType(data[dataOffset:])
		switch blockType {
		case 1:
			s4data.MasterKey, err = S4Type1Decode(data[dataOffset : dataOffset+length])
			if err != nil {
				return nil, err
			}
			dataOffset += length
		case 2:
			s4data.RescueCode, err = S4Type2Decode(data[dataOffset : dataOffset+length])
			if err != nil {
				return nil, err
			}
			dataOffset += length
			/*
				case 3:
					s4data.PreviousIdentities, err = S4Type3Decode(data[dataOffset : dataOffset+length])
					if err != nil {
						return nil, err
					}
					dataOffset += length
			*/
		default:
			log.Printf("Unknown block type in sqrldata: %v", blockType)
			s4data.Others = append(s4data.Others, data[dataOffset:dataOffset+length])
			dataOffset += length
		}
	}

	return s4data, nil
}

func peekType(data []byte) (int, int) {
	if len(data) < 4 {
		return 0, 0
	}
	len := binary.LittleEndian.Uint16(data[0:])
	typ := binary.LittleEndian.Uint16(data[2:])
	return int(len), int(typ)
}

type S4Data struct {
	MasterKey          *S4Type1
	RescueCode         *S4Type2
	PreviousIdentities *S4Type3
	Others             [][]byte
}

// S4Type1 Password encrypted data
type S4Type1 struct {
	Length                uint16   // == 125
	Type                  uint16   // == 1
	PlainLength           uint16   // == 45
	AESGCMIV              [12]byte // 12
	ScryptSalt            [16]byte // 16
	ScryptN               byte
	ScryptIterations      uint32
	OptionFlags           uint16
	HintLength            byte
	PasswordVerifySeconds byte
	IdleTimeoutMinutes    uint16

	EncryptedIdentityMasterKey [32]byte // 32
	EncryptedIdentityLockKey   [32]byte // 32
	VerificationTag            [16]byte // 16
}

func S4Type1Decode(e []byte) (*S4Type1, error) {
	if len(e) != 125 {
		return nil, fmt.Errorf("Wrong T1 input length: %v", len(e))
	}
	t := &S4Type1{
		Length:      binary.LittleEndian.Uint16(e[0:]),
		Type:        binary.LittleEndian.Uint16(e[2:]),
		PlainLength: binary.LittleEndian.Uint16(e[4:]),
		//AESGCMIV:                   e[6:18],
		//ScryptSalt:                 e[18:34],
		ScryptN:               e[34],
		ScryptIterations:      binary.LittleEndian.Uint32(e[35:]),
		OptionFlags:           binary.LittleEndian.Uint16(e[39:]),
		HintLength:            e[41],
		PasswordVerifySeconds: e[42],
		IdleTimeoutMinutes:    binary.LittleEndian.Uint16(e[43:]),
		//EncryptedIdentityMasterKey: e[45:77],
		//EncryptedIdentityLockKey:   e[77:109],
		//VerificationTag:            e[109:],
	}
	copy(t.AESGCMIV[:], e[6:18])
	copy(t.ScryptSalt[:], e[18:34])
	copy(t.EncryptedIdentityMasterKey[:], e[45:77])
	copy(t.EncryptedIdentityLockKey[:], e[77:109])
	copy(t.VerificationTag[:], e[109:])
	return t, nil
}

func (s4 *S4Type1) String() string {
	return fmt.Sprintf("%#v", s4)
}

func (s4 *S4Type1) Encode() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 125))

	binary.Write(buf, binary.LittleEndian, s4.Length)
	binary.Write(buf, binary.LittleEndian, s4.Type)
	binary.Write(buf, binary.LittleEndian, s4.PlainLength)
	binary.Write(buf, binary.LittleEndian, s4.AESGCMIV)
	binary.Write(buf, binary.LittleEndian, s4.ScryptSalt)
	binary.Write(buf, binary.LittleEndian, s4.ScryptN)
	binary.Write(buf, binary.LittleEndian, s4.ScryptIterations)
	binary.Write(buf, binary.LittleEndian, s4.OptionFlags)
	binary.Write(buf, binary.LittleEndian, s4.HintLength)
	binary.Write(buf, binary.LittleEndian, s4.PasswordVerifySeconds)
	binary.Write(buf, binary.LittleEndian, s4.IdleTimeoutMinutes)
	binary.Write(buf, binary.LittleEndian, s4.EncryptedIdentityMasterKey)
	binary.Write(buf, binary.LittleEndian, s4.EncryptedIdentityLockKey)
	binary.Write(buf, binary.LittleEndian, s4.VerificationTag)

	return buf.Bytes()
}

// S4Type2 RescueCode encrypted data
type S4Type2 struct {
	Length           uint16   // == 73
	Type             uint16   // == 2
	ScryptSalt       [16]byte // 16
	ScryptN          byte
	ScryptIterations uint32

	EncryptedIdentityUnlockKey [32]byte // 32
	VerificationTag            [16]byte // 16
}

func S4Type2Decode(e []byte) (*S4Type2, error) {
	if len(e) != 73 {
		return nil, fmt.Errorf("Wrong T2 input length: %v", len(e))
	}
	t := &S4Type2{
		Length: binary.LittleEndian.Uint16(e[0:]),
		Type:   binary.LittleEndian.Uint16(e[2:]),
		//ScryptSalt: e[4:20],
		ScryptN:          e[20],
		ScryptIterations: binary.LittleEndian.Uint32(e[21:]),
		//EncryptedIdentityUnlockKey: e[25:57],
		//VerificationTag: e[57:]
	}
	copy(t.ScryptSalt[:], e[4:20])
	copy(t.EncryptedIdentityUnlockKey[:], e[25:57])
	copy(t.VerificationTag[:], e[57:])
	return t, nil
}

func (s4 *S4Type2) String() string {
	return fmt.Sprintf("%#v", s4)
}

// S4Type3 Previous identities encrypted data
type S4Type3 struct {
	Length  uint16 // == 54,86,118,150 (+32 for each previous key)
	Type    uint16 // == 2
	Edition uint16

	// array of previous keys sorted with oldest last
	EncryptedIdentityPreviousUnlockKey [][32]byte
	VerificationTag                    [16]byte // 16
}

func S4Type3Decode(e []byte) (*S4Type3, error) {
	if len(e) != 54 || len(e) != 86 || len(e) != 118 || len(e) != 150 {
		return nil, fmt.Errorf("Wrong T3 input length: %v", len(e))
	}
	t := &S4Type3{
		Length:  binary.LittleEndian.Uint16(e[0:]),
		Type:    binary.LittleEndian.Uint16(e[2:]),
		Edition: binary.LittleEndian.Uint16(e[4:]),
		//EncryptedIdentityUnlockKey: e[6:38],
		//VerificationTag: e[38:]
	}
	pcount := (len(e) - 22) / 32
	for i := 0; i < pcount; i++ {
		var puk [32]byte
		startoffset := 6 + i*32
		copy(puk[:], e[startoffset:startoffset+32])
		t.EncryptedIdentityPreviousUnlockKey = append(t.EncryptedIdentityPreviousUnlockKey, puk)
	}
	copy(t.VerificationTag[:], e[6+pcount*32:])
	return t, nil
}

func (s4 *S4Type3) String() string {
	return fmt.Sprintf("%#v", s4)
}
