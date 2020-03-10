package h2c

import (
	"hash"
	"math/big"

	M "github.com/armfazh/h2c-go-ref/mapping"
	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

// HashToPoint represents a complete and secure function for hashing strings to points.
type HashToPoint interface {
	// IsRandomOracle returns true if the output distribution is
	// indifferentiable from a random oracle.
	IsRandomOracle() bool
	// Hash returns a point on an elliptic curve given as input a string and a
	// domain separation tag.
	Hash(in, dst []byte) C.Point
	// GetCurve returns the destination elliptic curve.
	GetCurve() C.EllCurve
}

type encoding struct {
	E            C.EllCurve
	HFunc        func() hash.Hash
	L            uint
	Mapping      M.MapToCurve
	RandomOracle bool
	expand       Expander
}

// Expander is
type Expander int

const (
	// XMD is
	XMD Expander = iota
	// XOF is
	XOF
	// OTHER is
	OTHER
)

func (e *encoding) expandMessage(msg []byte, dst []byte, n uint) []byte {
	if len(dst) > 255 {
		H := e.HFunc()
		_, _ = H.Write([]byte("H2C-OVERSIZE-DST-"))
		_, _ = H.Write(dst)
		dst = H.Sum(nil)
	}
	switch e.expand {
	case XMD:
		return e.expandMessageXMD(msg, dst, n)
	case XOF:
		return e.expandMessageXOF(msg, dst, n)
	default:
		panic("Not implemented")
	}
}
func (e *encoding) expandMessageXOF(msg []byte, dst []byte, n uint) []byte {
	dstPrime := []byte{byte(len(dst))}
	bLen := []byte{0, 0}
	bLen[0] = byte((n >> 8) & 0xFF)
	bLen[1] = byte(n & 0xFF)
	pseudo := make([]byte, n)

	H := e.HFunc()
	_, _ = H.Write(msg)
	_, _ = H.Write(bLen)
	_, _ = H.Write(dstPrime)
	// _, _ = H.Read(mspPrime)  // This should be read/write expander
	return pseudo
}

func (e *encoding) expandMessageXMD(msg []byte, dst []byte, n uint) []byte {
	H := e.HFunc()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic("too big")
	}
	dstPrime := []byte{byte(len(dst))}
	dstPrime = append(dstPrime, dst...)
	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)
	b := make([][]byte, ell+1)

	H.Reset()
	_, _ = H.Write(zPad)
	_, _ = H.Write(msg)
	_, _ = H.Write(libStr)
	_, _ = H.Write([]byte{0})
	_, _ = H.Write(dstPrime)
	b[0] = H.Sum(nil)

	H.Reset()
	_, _ = H.Write(b[0])
	_, _ = H.Write([]byte{1})
	_, _ = H.Write(dstPrime)
	b[1] = H.Sum(nil)
	pseudo := append([]byte{}, b[1]...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		_, _ = H.Write(xor(b[0], b[i-1]))
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(dstPrime)
		b[i] = H.Sum(nil)
		pseudo = append(pseudo, b[i]...)
	}
	return pseudo[0:n]
}

func xor(x, y []byte) []byte {
	if len(x) != len(y) {
		panic("slices must have same size")
	}
	z := make([]byte, len(x))
	for i := range x {
		z[i] = x[i] ^ y[i]
	}
	return z
}

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func (e *encoding) hashToField(
	msg []byte, // msg is the message to hash.
	dst []byte, // DST, a domain separation tag (see discussion above).
	count uint, // count is 1 or 2.
) []GF.Elt {
	F := e.E.Field()
	m := F.Ext()
	length := count * m * e.L
	pseudo := e.expandMessage(msg, dst, length)

	u := make([]GF.Elt, count)
	v := make([]interface{}, m)
	for i := uint(0); i < count; i++ {
		for j := uint(0); j < m; j++ {
			offset := e.L * (j + i*m)
			t := pseudo[offset : offset+e.L]
			vj := new(big.Int).SetBytes(t)
			v[j] = vj.Mod(vj, F.P())
		}
		u[i] = F.Elt(v)
	}
	return u
}

func (e *encoding) GetCurve() C.EllCurve { return e.E }
func (e *encoding) IsRandomOracle() bool { return e.RandomOracle }

type encodeToCurve struct{ *encoding }

func (s *encodeToCurve) Hash(in, dst []byte) C.Point {
	u := s.hashToField(in, dst, 1)
	Q := s.Mapping.Map(u[0])
	P := s.E.ClearCofactor(Q)
	return P
}

type hashToCurve struct{ *encoding }

func (s *hashToCurve) Hash(in, dst []byte) C.Point {
	u := s.hashToField(in, dst, 2)
	Q0 := s.Mapping.Map(u[0])
	Q1 := s.Mapping.Map(u[1])
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}
