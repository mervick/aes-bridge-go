package aesbridge

import (
    "crypto/rand"
    "crypto/sha256"
    "sync/atomic"
    "errors"
)

var nonceCounter uint64

func generateRandom(size int) []byte {
    nonce := atomic.AddUint64(&nonceCounter, 1)
    b := make([]byte, 13+8+13)
    rand.Read(b[:13])
    copy(b[13:21], u64ToBytes(nonce))
    rand.Read(b[21:])
    hash := sha256.Sum256(b)
    return hash[:size]
}

func u64ToBytes(n uint64) []byte {
    out := make([]byte, 8)
    for i := 7; i >= 0; i-- {
        out[i] = byte(n)
        n >>= 8
    }
    return out
}

func toBytes(data any) ([]byte, error) {
    switch v := data.(type) {
    case string:
        return []byte(v), nil
    case []byte:
        return v, nil
    default:
        return nil, errors.New("unsupported type")
    }
}

func toString(data any) (string, error) {
    switch v := data.(type) {
    case string:
        return v, nil
    case []byte:
        return string(v), nil
    default:
        return "", errors.New("unsupported type")
    }
}
