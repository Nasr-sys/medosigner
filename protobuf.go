package medosigner

import (
	"errors"
	"fmt"
)

type ProtoFieldType int

const (
	VARINT     ProtoFieldType = 0
	INT64      ProtoFieldType = 1
	STRING     ProtoFieldType = 2
	GROUPSTART ProtoFieldType = 3
	GROUPEND   ProtoFieldType = 4
	INT32      ProtoFieldType = 5
	ERROR1     ProtoFieldType = 6
	ERROR2     ProtoFieldType = 7
)

func (t ProtoFieldType) String() string {
	switch t {
	case VARINT:
		return "VARINT"
	case INT64:
		return "INT64"
	case STRING:
		return "STRING"
	case GROUPSTART:
		return "GROUPSTART"
	case GROUPEND:
		return "GROUPEND"
	case INT32:
		return "INT32"
	default:
		return "UNKNOWN"
	}
}

type ProtoField struct {
	Idx  int
	Type ProtoFieldType
	Val  interface{}
}

func (pf *ProtoField) IsAsciiStr() bool {
	data, ok := pf.Val.([]byte)
	if !ok {
		return false
	}
	for _, b := range data {
		if b < 0x20 || b > 0x7e {
			return false
		}
	}
	return true
}

func (pf *ProtoField) String() string {
	switch pf.Type {
	case INT32, INT64, VARINT:
		return fmt.Sprintf("%d(%s): %v", pf.Idx, pf.Type.String(), pf.Val)
	case STRING:
		if pf.IsAsciiStr() {
			if data, ok := pf.Val.([]byte); ok {
				return fmt.Sprintf("%d(%s): \"%s\"", pf.Idx, pf.Type.String(), string(data))
			}
		}
		if data, ok := pf.Val.([]byte); ok {
			return fmt.Sprintf("%d(%s): h\"%x\"", pf.Idx, pf.Type.String(), data)
		}
		return fmt.Sprintf("%d(%s): %v", pf.Idx, pf.Type.String(), pf.Val)
	default:
		return fmt.Sprintf("%d(%s): %v", pf.Idx, pf.Type.String(), pf.Val)
	}
}

type ProtoReader struct {
	data []byte
	pos  int
}

func NewProtoReader(data []byte) *ProtoReader {
	return &ProtoReader{data: data, pos: 0}
}

func (r *ProtoReader) Seek(pos int) {
	r.pos = pos
}

func (r *ProtoReader) IsRemain(length int) bool {
	return r.pos+length <= len(r.data)
}

func (r *ProtoReader) Read0() byte {
	if !r.IsRemain(1) {
		panic("EOF")
	}
	ret := r.data[r.pos]
	r.pos++
	return ret
}

func (r *ProtoReader) Read(length int) []byte {
	if !r.IsRemain(length) {
		panic("EOF")
	}
	ret := r.data[r.pos : r.pos+length]
	r.pos += length
	return ret
}

func (r *ProtoReader) ReadInt32() uint32 {
	return uint32(r.Read(4)[0]) | uint32(r.Read(4)[1])<<8 | uint32(r.Read(4)[2])<<16 | uint32(r.Read(4)[3])<<24
}

func (r *ProtoReader) ReadInt64() uint64 {
	data := r.Read(8)
	return uint64(data[0]) | uint64(data[1])<<8 | uint64(data[2])<<16 | uint64(data[3])<<24 |
		uint64(data[4])<<32 | uint64(data[5])<<40 | uint64(data[6])<<48 | uint64(data[7])<<56
}

func (r *ProtoReader) ReadVarint() uint64 {
	var vint uint64
	n := 0
	for {
		byte := r.Read0()
		vint |= uint64(byte&0x7F) << (7 * n)
		if byte < 0x80 {
			break
		}
		n++
	}
	return vint
}

func (r *ProtoReader) ReadString() []byte {
	length := r.ReadVarint()
	return r.Read(int(length))
}

type ProtoWriter struct {
	data []byte
}

func NewProtoWriter() *ProtoWriter {
	return &ProtoWriter{data: make([]byte, 0)}
}

func (w *ProtoWriter) Write0(byte byte) {
	w.data = append(w.data, byte)
}

func (w *ProtoWriter) Write(bytes []byte) {
	w.data = append(w.data, bytes...)
}

func (w *ProtoWriter) WriteInt32(int32 uint32) {
	w.Write([]byte{
		byte(int32),
		byte(int32 >> 8),
		byte(int32 >> 16),
		byte(int32 >> 24),
	})
}

func (w *ProtoWriter) WriteInt64(int64 uint64) {
	w.Write([]byte{
		byte(int64),
		byte(int64 >> 8),
		byte(int64 >> 16),
		byte(int64 >> 24),
		byte(int64 >> 32),
		byte(int64 >> 40),
		byte(int64 >> 48),
		byte(int64 >> 56),
	})
}

func (w *ProtoWriter) WriteVarint(vint uint64) {
	for vint > 0x80 {
		w.Write0(byte((vint & 0x7F) | 0x80))
		vint >>= 7
	}
	w.Write0(byte(vint & 0x7F))
}

func (w *ProtoWriter) WriteString(bytes []byte) {
	w.WriteVarint(uint64(len(bytes)))
	w.Write(bytes)
}

func (w *ProtoWriter) ToBytes() []byte {
	return w.data
}

type ProtoBuf struct {
	fields []*ProtoField
}

func NewProtoBuf(data interface{}) (*ProtoBuf, error) {
	pb := &ProtoBuf{fields: make([]*ProtoField, 0)}
	if data == nil {
		return pb, nil
	}
	switch v := data.(type) {
	case []byte:
		if len(v) > 0 {
			if err := pb.parseBuf(v); err != nil {
				return nil, err
			}
		}
	case map[int]interface{}:
		if len(v) > 0 {
			if err := pb.parseDict(v); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("unsupported type to protobuf")
	}
	return pb, nil
}

func (pb *ProtoBuf) parseBuf(bytes []byte) error {
	reader := NewProtoReader(bytes)
	for reader.IsRemain(1) {
		key := reader.ReadVarint()
		fieldType := ProtoFieldType(key & 0x7)
		fieldIdx := int(key >> 3)
		if fieldIdx == 0 {
			break
		}
		switch fieldType {
		case INT32:
			pb.Put(&ProtoField{Idx: fieldIdx, Type: fieldType, Val: reader.ReadInt32()})
		case INT64:
			pb.Put(&ProtoField{Idx: fieldIdx, Type: fieldType, Val: reader.ReadInt64()})
		case VARINT:
			pb.Put(&ProtoField{Idx: fieldIdx, Type: fieldType, Val: reader.ReadVarint()})
		case STRING:
			pb.Put(&ProtoField{Idx: fieldIdx, Type: fieldType, Val: reader.ReadString()})
		default:
			return fmt.Errorf("parse protobuf error, unexpected field type: %d", fieldType)
		}
	}
	return nil
}

func (pb *ProtoBuf) ToBuf() []byte {
	writer := NewProtoWriter()
	for _, field := range pb.fields {
		key := uint64((field.Idx << 3) | int(field.Type&7))
		writer.WriteVarint(key)
		switch field.Type {
		case INT32:
			writer.WriteInt32(field.Val.(uint32))
		case INT64:
			writer.WriteInt64(field.Val.(uint64))
		case VARINT:
			writer.WriteVarint(field.Val.(uint64))
		case STRING:
			writer.WriteString(field.Val.([]byte))
		}
	}
	return writer.ToBytes()
}

func (pb *ProtoBuf) Dump() {
	for _, field := range pb.fields {
		fmt.Println(field)
	}
}

func (pb *ProtoBuf) GetList(idx int) []*ProtoField {
	result := make([]*ProtoField, 0)
	for _, field := range pb.fields {
		if field.Idx == idx {
			result = append(result, field)
		}
	}
	return result
}

func (pb *ProtoBuf) Get(idx int) *ProtoField {
	for _, field := range pb.fields {
		if field.Idx == idx {
			return field
		}
	}
	return nil
}

func (pb *ProtoBuf) GetInt(idx int) uint64 {
	field := pb.Get(idx)
	if field == nil {
		return 0
	}
	switch v := field.Val.(type) {
	case uint32:
		return uint64(v)
	case uint64:
		return v
	default:
		return 0
	}
}

func (pb *ProtoBuf) GetBytes(idx int) []byte {
	field := pb.Get(idx)
	if field == nil {
		return nil
	}
	if field.Type == STRING {
		if data, ok := field.Val.([]byte); ok {
			return data
		}
	}
	return nil
}

func (pb *ProtoBuf) GetUtf8(idx int) string {
	data := pb.GetBytes(idx)
	if data == nil {
		return ""
	}
	return string(data)
}

func (pb *ProtoBuf) GetProtoBuf(idx int) (*ProtoBuf, error) {
	data := pb.GetBytes(idx)
	if data == nil {
		return nil, nil
	}
	return NewProtoBuf(data)
}

func (pb *ProtoBuf) Put(field *ProtoField) {
	pb.fields = append(pb.fields, field)
}

func (pb *ProtoBuf) PutInt32(idx int, val uint32) {
	pb.Put(&ProtoField{Idx: idx, Type: INT32, Val: val})
}

func (pb *ProtoBuf) PutInt64(idx int, val uint64) {
	pb.Put(&ProtoField{Idx: idx, Type: INT64, Val: val})
}

func (pb *ProtoBuf) PutVarint(idx int, val uint64) {
	pb.Put(&ProtoField{Idx: idx, Type: VARINT, Val: val})
}

func (pb *ProtoBuf) PutBytes(idx int, data []byte) {
	pb.Put(&ProtoField{Idx: idx, Type: STRING, Val: data})
}

func (pb *ProtoBuf) PutUtf8(idx int, data string) {
	pb.Put(&ProtoField{Idx: idx, Type: STRING, Val: []byte(data)})
}

func (pb *ProtoBuf) PutProtoBuf(idx int, data *ProtoBuf) {
	pb.Put(&ProtoField{Idx: idx, Type: STRING, Val: data.ToBuf()})
}

func (pb *ProtoBuf) parseDict(data map[int]interface{}) error {
    for k, v := range data {
        switch val := v.(type) {
        case int:
            pb.PutVarint(k, uint64(val))
        case int64:
            pb.PutVarint(k, uint64(val))  // أضف هذا
        case uint64:
            pb.PutVarint(k, val)
        case string:
            pb.PutUtf8(k, val)
        case []byte:
            pb.PutBytes(k, val)
        case map[int]interface{}:
            subPb, err := NewProtoBuf(val)
            if err != nil {
                return err
            }
            pb.PutProtoBuf(k, subPb)
        default:
            return fmt.Errorf("unsupported type to protobuf: %T", v)
        }
    }
    return nil
}

func (pb *ProtoBuf) ToDict(out map[int]interface{}) (map[int]interface{}, error) {
	for k := range out {
		switch out[k].(type) {
		case int:
			out[k] = int(pb.GetInt(k))
		case string:
			out[k] = pb.GetUtf8(k)
		case []byte:
			out[k] = pb.GetBytes(k)
		case map[int]interface{}:
			subPb, err := pb.GetProtoBuf(k)
			if err != nil {
				return nil, err
			}
			if subPb != nil {
				subDict := make(map[int]interface{})
				for sk := range out[k].(map[int]interface{}) {
					subDict[sk] = out[k].(map[int]interface{})[sk]
				}
				_, err = subPb.ToDict(subDict)
				if err != nil {
					return nil, err
				}
				out[k] = subDict
			}
		}
	}
	return out, nil
}
