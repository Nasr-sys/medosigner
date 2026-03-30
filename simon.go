package medosigner

func rotateLeft(v uint64, n uint) uint64 {
	return (v << n) | (v >> (64 - n))
}

func rotateRight(v uint64, n uint) uint64 {
	return (v >> n) | (v << (64 - n))
}

func keyExpansion(key []uint64) []uint64 {
	expanded := make([]uint64, 72)
	copy(expanded[:4], key[:4])

	for i := 4; i < 72; i++ {
		tmp := rotateRight(expanded[i-1], 3)
		tmp ^= expanded[i-3]
		tmp ^= rotateRight(tmp, 1)
		expanded[i] = ^expanded[i-4] ^ tmp ^ getBit(0x3DC94C3A046D678B, (i-4)%62) ^ 3
	}
	return expanded
}

func getBit(val uint64, pos int) uint64 {
	if (val>>pos)&1 == 1 {
		return 1
	}
	return 0
}

func SimonDec(ct []uint64, k []uint64, c int) []uint64 {
	key := keyExpansion(k)

	x_i := ct[0]
	x_i1 := ct[1]

	for i := 71; i >= 0; i-- {
		tmp := x_i
		var f uint64
		if c == 1 {
			f = rotateLeft(x_i, 1)
		} else {
			f = rotateLeft(x_i, 1) & rotateLeft(x_i, 8)
		}
		x_i = x_i1 ^ f ^ rotateLeft(x_i, 2) ^ key[i]
		x_i1 = tmp
	}

	return []uint64{x_i, x_i1}
}

func SimonEnc(pt []uint64, k []uint64, c int) []uint64 {
	key := keyExpansion(k)

	x_i := pt[0]
	x_i1 := pt[1]

	for i := 0; i < 72; i++ {
		tmp := x_i1
		var f uint64
		if c == 1 {
			f = rotateLeft(x_i1, 1)
		} else {
			f = rotateLeft(x_i1, 1) & rotateLeft(x_i1, 8)
		}
		x_i1 = x_i ^ f ^ rotateLeft(x_i1, 2) ^ key[i]
		x_i = tmp
	}

	return []uint64{x_i, x_i1}
}