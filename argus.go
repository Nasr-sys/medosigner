package medosigner

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "crypto/rand"
    "encoding/base64"
    "encoding/binary"
    "fmt"
    "strconv"
    "time"
)

type Argus struct{}

func (a *Argus) encryptEncPb(data []byte, l int) []byte {
    xorArray := make([]byte, 8)
    copy(xorArray, data[:8])

    result := make([]byte, l)
    copy(result, data)

    for i := 8; i < l; i++ {
        result[i] = data[i] ^ xorArray[i%8]
    }

    // reverse
    for i, j := 0, l-1; i < j; i, j = i+1, j-1 {
        result[i], result[j] = result[j], result[i]
    }
    return result
}

func (a *Argus) GetBodyHash(stub string) []byte {
    if stub == "" {
        sm3 := NewSM3()
        hash := sm3.Sm3Hash(make([]byte, 16))
        return hash[:6]
    }
    sm3 := NewSM3()
    data, _ := hexDecode(stub)
    hash := sm3.Sm3Hash(data)
    return hash[:6]
}

func (a *Argus) GetQueryHash(query string) []byte {
    if query == "" {
        sm3 := NewSM3()
        hash := sm3.Sm3Hash(make([]byte, 16))
        return hash[:6]
    }
    sm3 := NewSM3()
    hash := sm3.Sm3Hash([]byte(query))
    return hash[:6]
}

func hexDecode(s string) ([]byte, error) {
    if len(s)%2 != 0 {
        s = "0" + s
    }
    result := make([]byte, len(s)/2)
    for i := 0; i < len(s); i += 2 {
        var b byte
        for j := 0; j < 2; j++ {
            c := s[i+j]
            if c >= '0' && c <= '9' {
                b = (b << 4) | (c - '0')
            } else if c >= 'a' && c <= 'f' {
                b = (b << 4) | (c - 'a' + 10)
            } else if c >= 'A' && c <= 'F' {
                b = (b << 4) | (c - 'A' + 10)
            }
        }
        result[i/2] = b
    }
    return result, nil
}

func (a *Argus) Encrypt(xargusBean map[int]interface{}) (string, error) {
    pb, err := NewProtoBuf(xargusBean)
    if err != nil {
        return "", err
    }
    protobuf := pb.ToBuf()
    // PKCS7 padding
    paddedLen := ((len(protobuf) + 15) / 16) * 16
    padded := make([]byte, paddedLen)
    copy(padded, protobuf)
    PKCS7PaddingPadBuffer(padded, len(protobuf), paddedLen, 16)

    newLen := len(padded)

    signKey := []byte("\xac\x1a\xda\xae\x95\xa7\xaf\x94\xa5\x11J\xb3\xb3\xa9}\xd8\x00P\xaa\n91L@R\x8c\xae\xc9RV\xc2\x8c")
    // sm3_hash(sign_key + b'\xf2\x81ao' + sign_key)
    sm3Hash := []byte("\xfcx\xe0\xa9ez\x0ct\x8c\xe5\x15Y\x90<\xcf\x03Q\x0eQ\xd3\xcf\xf22\xd7\x13C\xe8\x8a2\x1cS\x04")

    key := sm3Hash[:32]
    keyList := make([]uint64, 4)
    for i := 0; i < 2; i++ {
        keyList[i*2] = binary.LittleEndian.Uint64(key[i*16 : i*16+8])
        keyList[i*2+1] = binary.LittleEndian.Uint64(key[i*16+8 : i*16+16])
    }

    encPb := make([]byte, newLen)
    for i := 0; i < newLen/16; i++ {
        pt := make([]uint64, 2)
        pt[0] = binary.LittleEndian.Uint64(padded[i*16 : i*16+8])
        pt[1] = binary.LittleEndian.Uint64(padded[i*16+8 : i*16+16])
        ct := SimonEnc(pt, keyList, 0)
        binary.LittleEndian.PutUint64(encPb[i*16:], ct[0])
        binary.LittleEndian.PutUint64(encPb[i*16+8:], ct[1])
    }

    buffer := make([]byte, newLen+8)
    copy(buffer[:8], []byte("\xf2\xf7\xfc\xff\xf2\xf7\xfc\xff"))
    copy(buffer[8:], encPb)

    bBuffer := a.encryptEncPb(buffer, newLen+8)
    bBuffer = append([]byte("\xa6n\xad\x9fw\x01\xd0\x0c\x18"), bBuffer...)
    bBuffer = append(bBuffer, []byte("ao")...)

    md5Hash := md5.Sum(signKey[:16])
    md5Key := md5.Sum(signKey[16:])
    cipher, err := NewAESCBC(md5Hash[:], md5Key[:])
    if err != nil {
        return "", err
    }

    paddedBBuffer := make([]byte, ((len(bBuffer)+15)/16)*16)
    copy(paddedBBuffer, bBuffer)
    PKCS7PaddingPadBuffer(paddedBBuffer, len(bBuffer), len(paddedBBuffer), 16)

    encrypted, err := cipher.Encrypt(paddedBBuffer)
    if err != nil {
        return "", err
    }
    result := append([]byte("\xf2\x81"), encrypted...)
    return base64.StdEncoding.EncodeToString(result), nil
}

type AESCBC struct {
    key []byte
    iv  []byte
}

func NewAESCBC(key, iv []byte) (*AESCBC, error) {
    return &AESCBC{key: key, iv: iv}, nil
}

func (c *AESCBC) Encrypt(data []byte) ([]byte, error) {
    block, err := aes.NewCipher(c.key)
    if err != nil {
        return nil, err
    }

    if len(data)%aes.BlockSize != 0 {
        return nil, fmt.Errorf("data is not padded")
    }

    mode := cipher.NewCBCEncrypter(block, c.iv)
    encrypted := make([]byte, len(data))
    mode.CryptBlocks(encrypted, data)

    return encrypted, nil
}

func (a *Argus) GetSign(queryhash string, data string, timestamp int64, aid int, licenseId int, platform int, secDeviceId string, sdkVersion string, sdkVersionInt int) (string, error) {
    if timestamp == 0 {
        timestamp = time.Now().Unix()
    }

    xargusBean := map[int]interface{}{
        1:  uint64(0x20200929 << 1),
        2:  uint64(2),
        3:  uint64(randInt(0, 0x7FFFFFFF)),
        4:  strconv.Itoa(aid),
        5:  "device_id_placeholder",
        6:  strconv.Itoa(licenseId),
        7:  "version_name_placeholder",
        8:  sdkVersion,
        9:  uint64(sdkVersionInt),
        10: make([]byte, 8),
        11: uint64(platform),
        12: uint64(timestamp << 1),
        13: a.GetBodyHash(data),
        14: a.GetQueryHash(queryhash),
        15: map[int]interface{}{
            1: uint64(1),
            2: uint64(1),
            3: uint64(1),
            7: uint64(3348294860),
        },
        16: secDeviceId,
        20: "none",
        21: uint64(738),
        23: map[int]interface{}{
            1: "NX551J",
            2: uint64(8196),
            4: uint64(2162219008),
        },
        25: uint64(2),
    }

    return a.Encrypt(xargusBean)
}

func randInt(min, max int) int {
    b := make([]byte, 4)
    rand.Read(b)
    return min + int(binary.BigEndian.Uint32(b))%(max-min)
}
