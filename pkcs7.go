package medosigner

func PKCS7PaddingDataLength(buffer []byte, bufferSize int, modulus int) int {
	if bufferSize%modulus != 0 || bufferSize < modulus {
		return 0
	}
	paddingValue := int(buffer[bufferSize-1])
	if paddingValue < 1 || paddingValue > modulus {
		return 0
	}
	if bufferSize < paddingValue+1 {
		return 0
	}
	bufferSize--
	for i := 1; i < paddingValue; i++ {
		bufferSize--
		if int(buffer[bufferSize]) != paddingValue {
			return 0
		}
	}
	return bufferSize
}

func PKCS7PaddingPadBuffer(buffer []byte, dataLength int, bufferSize int, modulus int) int {
	padByte := modulus - (dataLength % modulus)
	if dataLength+padByte > bufferSize {
		return -padByte
	}
	for i := 0; i < padByte; i++ {
		buffer[dataLength+i] = byte(padByte)
	}
	return padByte
}

func PaddingSize(size int) int {
	mod := size % 16
	if mod > 0 {
		return size + (16 - mod)
	}
	return size
}