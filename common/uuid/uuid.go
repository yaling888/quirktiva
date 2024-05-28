package uuid

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/yaling888/quirktiva/common/encoding/base58"
)

const (
	invalid uint8 = iota
	b58Hlf
	b64Hlf
	b58
	b64
	std
)

const hexTable = "0123456789abcdef"

type UUID struct {
	hi uint64
	lo uint64
	tp uint8
}

func Random() UUID {
	return randomUUID(std)
}

func RandomB64() UUID {
	return randomUUID(b64)
}

func RandomB64Hlf() UUID {
	return randomUUID(b64Hlf)
}

func RandomB58() UUID {
	return randomUUID(b58)
}

func RandomB58Hlf() UUID {
	return randomUUID(b58Hlf)
}

func Parse(s string) (UUID, error) {
	switch len(s) {
	case 32, 36, 34, 38, 41, 45:
		return ParseStd(s)
	case 22:
		return ParseB64(s)
	case 11:
		return ParseB64Hlf(s)
	}
	return UUID{}, fmt.Errorf("unable to parse UUID: %s", s)
}

func ParseStd(s string) (UUID, error) {
	switch len(s) {
	case 32: // hash
	case 36: // canonical
	case 34, 38:
		if s[0] != '{' || s[len(s)-1] != '}' {
			return UUID{}, fmt.Errorf("uuid: incorrect UUID format in string %s", s)
		}
		s = s[1 : len(s)-1]
	case 41, 45:
		if s[:9] != "urn:uuid:" {
			return UUID{}, fmt.Errorf("uuid: incorrect UUID format in string %q", s[:9])
		}
		s = s[9:]
	default:
		return UUID{}, fmt.Errorf("uuid: incorrect UUID length %d in string %q", len(s), s)
	}

	u := make([]byte, 16)

	// canonical
	if len(s) == 36 {
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return UUID{}, fmt.Errorf("uuid: incorrect UUID format in string %q", s)
		}
		for i, x := range [16]byte{
			0, 2, 4, 6,
			9, 11,
			14, 16,
			19, 21,
			24, 26, 28, 30, 32, 34,
		} {
			v1 := fromHexChar(s[x])
			v2 := fromHexChar(s[x+1])
			if v1|v2 == 255 {
				return UUID{}, fmt.Errorf("invalid UUID format: %s", s)
			}
			u[i] = (v1 << 4) | v2
		}
		return FromStd(u), nil
	}
	// hash like
	for i := 0; i < 32; i += 2 {
		v1 := fromHexChar(s[i])
		v2 := fromHexChar(s[i+1])
		if v1|v2 == 255 {
			return UUID{}, fmt.Errorf("invalid UUID format: %s", s)
		}
		u[i/2] = (v1 << 4) | v2
	}
	return FromStd(u), nil
}

func ParseB64(s string) (UUID, error) {
	if len(s) != 22 {
		return UUID{}, fmt.Errorf("uuid: incorrect UUID length %d in string %s", len(s), s)
	}
	dst := make([]byte, 16)
	_, err := base64.RawURLEncoding.Decode(dst, []byte(s))
	if err != nil {
		return UUID{}, err
	}
	return FromB64(dst), nil
}

func ParseB64Hlf(s string) (UUID, error) {
	if len(s) != 11 {
		return UUID{}, fmt.Errorf("uuid: incorrect UUID length %d in string %s", len(s), s)
	}
	dst := make([]byte, 8)
	_, err := base64.RawURLEncoding.Decode(dst, []byte(s))
	if err != nil {
		return UUID{}, err
	}
	return FromB64Hlf(dst), nil
}

func ParseB58(s string) (UUID, error) {
	l := len(s)
	if l != 22 && l != 21 {
		return UUID{}, fmt.Errorf("uuid: incorrect UUID length %d in string %s", l, s)
	}
	dst := base58.Decode(s)
	uuid, ok := fromSlice(dst, b58)
	if !ok {
		return UUID{}, fmt.Errorf("unable to parse UUID: %s", s)
	}
	return uuid, nil
}

func ParseB58Hlf(s string) (UUID, error) {
	l := len(s)
	if l != 11 && l != 10 {
		return UUID{}, fmt.Errorf("uuid: incorrect UUID length %d in string %s", l, s)
	}
	dst := base58.Decode(s)
	uuid, ok := fromSlice(dst, b58Hlf)
	if !ok {
		return UUID{}, fmt.Errorf("unable to parse UUID: %s", s)
	}
	return uuid, nil
}

func FromStd(src []byte) (uuid UUID) {
	uuid, _ = fromSlice(src, std)
	return
}

func FromB64(src []byte) (uuid UUID) {
	uuid, _ = fromSlice(src, b64)
	return
}

func FromB64Hlf(src []byte) (uuid UUID) {
	uuid, _ = fromSlice(src, b64Hlf)
	return
}

func FromB58(src []byte) (uuid UUID) {
	uuid, _ = fromSlice(src, b58)
	return
}

func FromB58Hlf(src []byte) (uuid UUID) {
	uuid, _ = fromSlice(src, b58Hlf)
	return
}

func fromSlice(slice []byte, tp uint8) (uuid UUID, ok bool) {
	switch len(slice) {
	case 8:
		if tp != b58Hlf && tp != b64Hlf {
			return UUID{}, false
		}
		return UUID{
			hi: 0,
			lo: binary.NativeEndian.Uint64(slice),
			tp: tp,
		}, true
	case 16:
		return UUID{
			hi: binary.NativeEndian.Uint64(slice[:8]),
			lo: binary.NativeEndian.Uint64(slice[8:]),
			tp: tp,
		}, true
	}
	return UUID{}, false
}

func randomUUID(t uint8) UUID {
	l := 16
	if t == b58Hlf || t == b64Hlf {
		l = 8
	}
	u := make([]byte, l)
	_, err := rand.Read(u)
	if err != nil {
		return UUID{}
	}
	if l == 16 { // v4
		u[6] = (u[6] & 0x0f) | 0x40
		u[8] = (u[8] & 0x3f) | 0x80
	}
	uuid, _ := fromSlice(u, t)
	return uuid
}

func fromHexChar(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}

func encodeCanonical(u []byte) string {
	dst := make([]byte, 36)
	dst[8] = '-'
	dst[13] = '-'
	dst[18] = '-'
	dst[23] = '-'
	for i, x := range [16]byte{
		0, 2, 4, 6,
		9, 11,
		14, 16,
		19, 21,
		24, 26, 28, 30, 32, 34,
	} {
		c := u[i]
		dst[x] = hexTable[c>>4]
		dst[x+1] = hexTable[c&0x0f]
	}
	return string(dst)
}

func formatUUID(id UUID, tp uint8) string {
	switch tp {
	case std:
		u := make([]byte, 16)
		binary.NativeEndian.PutUint64(u[:8], id.hi)
		binary.NativeEndian.PutUint64(u[8:], id.lo)
		return encodeCanonical(u)
	case b64:
		u := make([]byte, 16)
		buf := make([]byte, 22)
		binary.NativeEndian.PutUint64(u[:8], id.hi)
		binary.NativeEndian.PutUint64(u[8:], id.lo)
		base64.RawURLEncoding.Encode(buf, u)
		return string(buf)
	case b64Hlf:
		u := make([]byte, 8)
		buf := make([]byte, 11)
		binary.NativeEndian.PutUint64(u, id.lo)
		base64.RawURLEncoding.Encode(buf, u)
		return string(buf)
	case b58:
		u := make([]byte, 16)
		binary.NativeEndian.PutUint64(u[:8], id.hi)
		binary.NativeEndian.PutUint64(u[8:], id.lo)
		return base58.Encode(u)
	case b58Hlf:
		u := make([]byte, 8)
		binary.NativeEndian.PutUint64(u, id.lo)
		return base58.Encode(u)
	default:
		return "invalid UUID"
	}
}

func (id UUID) IsValid() bool {
	return id.tp != invalid
}

func (id UUID) IsFull() bool {
	return id.hi != 0 && id.tp != invalid
}

func (id UUID) HighDigit() uint64 {
	return id.hi
}

func (id UUID) LowDigit() uint64 {
	return id.lo
}

func (id UUID) Bytes() []byte {
	if !id.IsValid() {
		return nil
	}
	if id.hi == 0 {
		u := make([]byte, 8)
		binary.NativeEndian.PutUint64(u, id.lo)
		return u
	}
	u := make([]byte, 16)
	binary.NativeEndian.PutUint64(u[:8], id.hi)
	binary.NativeEndian.PutUint64(u[8:], id.lo)
	return u
}

func (id UUID) String() string {
	return formatUUID(id, id.tp)
}

func (id UUID) StringStd() string {
	if !id.IsFull() {
		return "invalid UUID"
	}
	return formatUUID(id, std)
}

func (id UUID) String64() string {
	if !id.IsFull() {
		return "invalid UUID64"
	}
	return formatUUID(id, b64)
}

func (id UUID) String64Hlf() string {
	return formatUUID(id, b64Hlf)
}

func (id UUID) String58() string {
	if !id.IsFull() {
		return "invalid UUID58"
	}
	return formatUUID(id, b58)
}

func (id UUID) String58Hlf() string {
	return formatUUID(id, b58Hlf)
}

func (id UUID) Compare(id2 UUID) int {
	hi1, hi2 := id.hi, id2.hi
	if hi1 < hi2 {
		return -1
	}
	if hi1 > hi2 {
		return 1
	}
	lo1, lo2 := id.lo, id2.lo
	if lo1 < lo2 {
		return -1
	}
	if lo1 > lo2 {
		return 1
	}
	tp1, tp2 := id.tp, id2.tp
	if tp1 < tp2 {
		return -1
	}
	if tp1 > tp2 {
		return 1
	}
	return 0
}

func (id UUID) MarshalText() ([]byte, error) {
	if !id.IsValid() {
		return nil, nil
	}
	return []byte(id.String()), nil
}

func (id *UUID) UnmarshalText(b []byte) error {
	u, err := Parse(string(b))
	if err != nil {
		return err
	}
	*id = u
	return nil
}

func (id UUID) MarshalJSON() ([]byte, error) {
	if !id.IsValid() {
		return nil, nil
	}
	return json.Marshal(id.String())
}

func (id *UUID) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}
	u, err := Parse(s)
	if err != nil {
		return err
	}
	*id = u
	return nil
}

func (id UUID) MarshalBinary() ([]byte, error) {
	return id.Bytes(), nil
}

func (id *UUID) UnmarshalBinary(data []byte) error {
	var (
		u  UUID
		ok bool
	)
	switch len(data) {
	case 16:
		u, ok = fromSlice(data, std)
	case 8:
		u, ok = fromSlice(data, b64Hlf)
	}
	if ok {
		*id = u
		return nil
	}
	return fmt.Errorf("uuid: UUID must be exactly 16 bytes long, got %d bytes", len(data))
}
