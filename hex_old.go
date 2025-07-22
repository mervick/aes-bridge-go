//go:build !go1.21

package aesbridge

const hextable = "0123456789abcdef"

// FromHex decodes src into dst.
//
// Deprecated: This function is implemented for go1.20 support,
// use hex.Decode in go1.21+
func fromHex(dst []byte, src string) (int, error) {
    j := 0
    for i := 0; i < len(src); i += 2 {
        a, ok := fromHexChar(src[i])
        if !ok {
            return 0, hex.InvalidByteError(src[i])
        }
        b, ok := fromHexChar(src[i+1])
        if !ok {
            return 0, hex.InvalidByteError(src[i+1])
        }
        dst[j] = (a << 4) | b
        j++
    }
    return j, nil
}

func fromHexChar(c byte) (byte, bool) {
    switch {
    case '0' <= c && c <= '9':
        return c - '0', true
    case 'a' <= c && c <= 'f':
        return c - 'a' + 10, true
    case 'A' <= c && c <= 'F':
        return c - 'A' + 10, true
    }
    return 0, false
}


// AppendEncode appends the hex-encoded src to dst and returns the extended
// buffer.
func AppendEncode(dst, src []byte) []byte {
    for _, v := range src {
        dst = append(dst, hextable[v>>4], hextable[v&0x0f)
    }
    return dst
}
