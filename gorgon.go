package medosigner

import (
	"crypto/md5"
	"fmt"
	"strconv"
)

type Gorgon struct {
	unix    int64
	params  string
	data    string
	cookies string
}

func NewGorgon(params string, unix int64, data string, cookies string) *Gorgon {
	return &Gorgon{
		unix:    unix,
		params:  params,
		data:    data,
		cookies: cookies,
	}
}

func (g *Gorgon) hash(data string) string {
	hash := md5.Sum([]byte(data))
	return fmt.Sprintf("%x", hash)
}

func (g *Gorgon) getBaseString() string {
	baseStr := g.hash(g.params)
	if g.data != "" {
		baseStr += g.hash(g.data)
	} else {
		baseStr += "00000000000000000000000000000000"
	}
	if g.cookies != "" {
		baseStr += g.hash(g.cookies)
	} else {
		baseStr += "00000000000000000000000000000000"
	}
	return baseStr
}

func (g *Gorgon) GetValue() map[string]string {
	return g.encrypt(g.getBaseString())
}

func (g *Gorgon) encrypt(data string) map[string]string {
	length := 20
	key := []int{
		0xDF, 0x77, 0xB9, 0x40, 0xB9, 0x9B, 0x84, 0x83,
		0xD1, 0xB9, 0xCB, 0xD1, 0xF7, 0xC2, 0xB9, 0x85,
		0xC3, 0xD0, 0xFB, 0xC3,
	}

	paramList := make([]int, 0)
	for i := 0; i < 12; i += 4 {
		temp := data[8*i : 8*(i+1)]
		for j := 0; j < 4; j++ {
			val, _ := strconv.ParseInt(temp[j*2:(j+1)*2], 16, 64)
			paramList = append(paramList, int(val))
		}
	}
	paramList = append(paramList, []int{0x0, 0x6, 0xB, 0x1C}...)

	H := int(g.unix)
	paramList = append(paramList,
		(H&0xFF000000)>>24,
		(H&0x00FF0000)>>16,
		(H&0x0000FF00)>>8,
		(H&0x000000FF)>>0,
	)

	eorResultList := make([]int, length)
	for i := 0; i < length; i++ {
		eorResultList[i] = paramList[i] ^ key[i]
	}

	for i := 0; i < length; i++ {
		C := g.reverse(eorResultList[i])
		D := eorResultList[(i+1)%length]
		E := C ^ D
		F := g.rbitAlgorithm(E)
		H := ((F ^ 0xFFFFFFFF) ^ length) & 0xFF
		eorResultList[i] = H
	}

	result := ""
	for _, param := range eorResultList {
		result += g.hexString(param)
	}

	return map[string]string{
		"x-ss-req-ticket": strconv.FormatInt(g.unix*1000, 10),
		"x-khronos":       strconv.FormatInt(g.unix, 10),
		"x-gorgon":        fmt.Sprintf("0404b0d30000%s", result),
	}
}

func (g *Gorgon) rbitAlgorithm(num int) int {
	result := ""
	tmpString := fmt.Sprintf("%08b", num)
	for i := 0; i < 8; i++ {
		result += string(tmpString[7-i])
	}
	val, _ := strconv.ParseInt(result, 2, 64)
	return int(val)
}

func (g *Gorgon) hexString(num int) string {
	tmpString := fmt.Sprintf("%02x", num)
	if len(tmpString) < 2 {
		tmpString = "0" + tmpString
	}
	return tmpString
}

func (g *Gorgon) reverse(num int) int {
	tmpString := g.hexString(num)
	reversed, _ := strconv.ParseInt(tmpString[1:]+tmpString[:1], 16, 64)
	return int(reversed)
}