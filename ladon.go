package medosigner

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strconv"
)

func md5Bytes(data string) string {
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func getTypeData(ptr []byte, index int, dataType string) uint64 {
	if dataType == "uint64_t" {
		return binary.LittleEndian.Uint64(ptr[index*8 : (index+1)*8])
	}
	return 0
}

func setTypeData(ptr []byte, index int, data uint64, dataType string) {
	if dataType == "uint64_t" {
		binary.LittleEndian.PutUint64(ptr[index*8:(index+1)*8], data)
	}
}

func validate(num uint64) uint64 {
	return num & 0xFFFFFFFFFFFFFFFF
}

func ror(value uint64, count int) uint64 {
	nbits := 64
	count %= nbits
	low := value << (nbits - count)
	return (value >> count) | low
}

func encryptLadonInput(hashTable []byte, inputData []byte) []byte {
	data0 := binary.LittleEndian.Uint64(inputData[:8])
	data1 := binary.LittleEndian.Uint64(inputData[8:])

	for i := 0; i < 0x22; i++ {
		hash := binary.LittleEndian.Uint64(hashTable[i*8 : (i+1)*8])
		data1 = validate(hash ^ (data0 + ((data1>>8)|(data1<<(64-8)))))
		data0 = validate(data1 ^ ((data0 >> 0x3D) | (data0 << (64 - 0x3D))))
	}

	output := make([]byte, 16)
	binary.LittleEndian.PutUint64(output[:8], data0)
	binary.LittleEndian.PutUint64(output[8:], data1)
	return output
}

func encryptLadon(md5hex string, data []byte, size int) []byte {
	hashTable := make([]byte, 272+16)
	copy(hashTable[:32], []byte(md5hex))

	temp := make([]uint64, 0)
	for i := 0; i < 4; i++ {
		temp = append(temp, binary.LittleEndian.Uint64(hashTable[i*8:(i+1)*8]))
	}

	bufferB0 := temp[0]
	bufferB8 := temp[1]
	temp = temp[2:]

	for i := 0; i < 0x22; i++ {
		x9 := bufferB0
		x8 := bufferB8
		x8 = validate(ror(x8, 8))
		x8 = validate(x8 + x9)
		x8 = validate(x8 ^ uint64(i))
		temp = append(temp, x8)
		x8 = validate(x8 ^ ror(x9, 61))
		setTypeData(hashTable, i+1, x8, "uint64_t")
		bufferB0 = x8
		bufferB8 = temp[0]
		temp = temp[1:]
	}

	newSize := PaddingSize(size)

	input := make([]byte, newSize)
	copy(input, data)
	PKCS7PaddingPadBuffer(input, size, newSize, 16)

	output := make([]byte, newSize)
	for i := 0; i < newSize/16; i++ {
		encrypted := encryptLadonInput(hashTable, input[i*16:(i+1)*16])
		copy(output[i*16:(i+1)*16], encrypted)
	}
	return output
}

func LadonEncrypt(khronos int, lcId int, aid int) string {
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)

	data := fmt.Sprintf("%d-%d-%d", khronos, lcId, aid)

	keygen := append(randomBytes, []byte(strconv.Itoa(aid))...)
	md5hex := md5Bytes(string(keygen))

	size := len(data)
	encrypted := encryptLadon(md5hex, []byte(data), size)

	output := make([]byte, 4+len(encrypted))
	copy(output[:4], randomBytes)
	copy(output[4:], encrypted)

	return base64.StdEncoding.EncodeToString(output)
}

type Ladon struct{}

func (l *Ladon) Encrypt(xKhronos int, lcId string, aid int) string {
	lcIdInt, _ := strconv.Atoi(lcId)
	return LadonEncrypt(xKhronos, lcIdInt, aid)
}