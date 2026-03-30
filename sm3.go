package medosigner

import (
	"encoding/binary"
)

type SM3 struct {
	IV []uint32
	TJ []uint32
}

func NewSM3() *SM3 {
	return &SM3{
		IV: []uint32{1937774191, 1226093241, 388252375, 3666478592, 2842636476, 372324522, 3817729613, 2969243214},
		TJ: []uint32{
			2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
			2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
			2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
			2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
			2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
			2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
			2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
			2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
		},
	}
}

func (s *SM3) rotateLeft(a uint32, k int) uint32 {
	k = k % 32
	return ((a << k) & 0xFFFFFFFF) | (a >> (32 - k))
}

func (s *SM3) FFJ(X, Y, Z uint32, j int) uint32 {
	if j >= 0 && j < 16 {
		return X ^ Y ^ Z
	}
	return (X & Y) | (X & Z) | (Y & Z)
}

func (s *SM3) GGJ(X, Y, Z uint32, j int) uint32 {
	if j >= 0 && j < 16 {
		return X ^ Y ^ Z
	}
	return (X & Y) | ((^X) & Z)
}

func (s *SM3) P0(X uint32) uint32 {
	return X ^ s.rotateLeft(X, 9) ^ s.rotateLeft(X, 17)
}

func (s *SM3) P1(X uint32) uint32 {
	return X ^ s.rotateLeft(X, 15) ^ s.rotateLeft(X, 23)
}

func (s *SM3) CF(V_i []uint32, B_i []byte) []uint32 {
	W := make([]uint32, 68)
	for i := 0; i < 16; i++ {
		W[i] = binary.BigEndian.Uint32(B_i[i*4 : (i+1)*4])
	}

	for j := 16; j < 68; j++ {
		W[j] = s.P1(W[j-16]^W[j-9]^s.rotateLeft(W[j-3], 15)) ^ s.rotateLeft(W[j-13], 7) ^ W[j-6]
	}

	W1 := make([]uint32, 64)
	for j := 0; j < 64; j++ {
		W1[j] = W[j] ^ W[j+4]
	}

	A, B, C, D, E, F, G, H := V_i[0], V_i[1], V_i[2], V_i[3], V_i[4], V_i[5], V_i[6], V_i[7]

	for j := 0; j < 64; j++ {
		SS1 := s.rotateLeft((s.rotateLeft(A, 12)+E+s.rotateLeft(s.TJ[j], j))&0xFFFFFFFF, 7)
		SS2 := SS1 ^ s.rotateLeft(A, 12)
		TT1 := (s.FFJ(A, B, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF
		TT2 := (s.GGJ(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF
		D = C
		C = s.rotateLeft(B, 9)
		B = A
		A = TT1
		H = G
		G = s.rotateLeft(F, 19)
		F = E
		E = s.P0(TT2)
	}

	return []uint32{
		A ^ V_i[0],
		B ^ V_i[1],
		C ^ V_i[2],
		D ^ V_i[3],
		E ^ V_i[4],
		F ^ V_i[5],
		G ^ V_i[6],
		H ^ V_i[7],
	}
}

func (s *SM3) Sm3Hash(msg []byte) []byte {
	msgBytes := make([]byte, len(msg))
	copy(msgBytes, msg)
	len1 := len(msgBytes)
	reserve1 := len1 % 64
	msgBytes = append(msgBytes, 0x80)
	reserve1++

	rangeEnd := 56
	if reserve1 > rangeEnd {
		rangeEnd += 64
	}

	for i := reserve1; i < rangeEnd; i++ {
		msgBytes = append(msgBytes, 0x00)
	}

	bitLength := uint64(len1) * 8
	bitLengthStr := make([]byte, 8)
	binary.BigEndian.PutUint64(bitLengthStr, bitLength)
	msgBytes = append(msgBytes, bitLengthStr...)

	groupCount := len(msgBytes) / 64
	B := make([][]byte, groupCount)
	for i := 0; i < groupCount; i++ {
		B[i] = msgBytes[i*64 : (i+1)*64]
	}

	V := make([][]uint32, groupCount+1)
	V[0] = s.IV
	for i := 0; i < groupCount; i++ {
		V[i+1] = s.CF(V[i], B[i])
	}

	result := make([]byte, 0, 32)
	for i := 0; i < 8; i++ {
		val := V[groupCount][i]
		result = append(result, byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	}
	return result
}