package h2c

import (
	"crypto"
	"io"
	"math/big"

	M "github.com/armfazh/h2c-go-ref/mapping"
	"github.com/armfazh/h2c-go-ref/xof"
	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

// HashToPoint represents a complete and secure function for hashing strings to points.
type HashToPoint interface {
	// IsRandomOracle returns true if the output distribution is
	// indifferentiable from a random oracle.
	IsRandomOracle() bool
	// Hash returns a point on an elliptic curve given a byte string.
	Hash(in []byte) C.Point
	// GetCurve returns the destination elliptic curve.
	GetCurve() C.EllCurve
}

type encoding struct {
	DST           []byte
	E             C.EllCurve
	expandMessage func([]byte, uint) []byte
	expanderID    uint
	L             uint
	Mapping       M.MapToCurve
	RandomOracle  bool
}

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func (e *encoding) hashToField(
	msg []byte, // msg is the message to hash.
	count uint, // count is 1 or 2.
) []GF.Elt {
	F := e.E.Field()
	m := F.Ext()
	length := count * m * e.L

	pseudo := e.expandMessage(msg, length)
	u := make([]GF.Elt, count)
	v := make([]interface{}, m)
	var vj big.Int
	p := F.P()
	for i := uint(0); i < count; i++ {
		for j := uint(0); j < m; j++ {
			offset := e.L * (j + i*m)
			t := pseudo[offset : offset+e.L]
			vj.SetBytes(t)
			v[j] = vj.Mod(&vj, p)
		}
		u[i] = F.Elt(v)
	}
	return u
}

func (e *encoding) expandMessageXOF(msg []byte, n uint) []byte {
	dstPrime := []byte{byte(len(e.DST))}
	bLen := []byte{0, 0}
	bLen[0] = byte((n >> 8) & 0xFF)
	bLen[1] = byte(n & 0xFF)
	pseudo := make([]byte, n)

	H := xof.XofID(e.expanderID).New()
	_, _ = H.Write(msg)
	_, _ = H.Write(bLen)
	_, _ = H.Write(dstPrime)
	_, err := io.ReadFull(H, pseudo)
	if err != nil {
		panic(err)
	}
	return pseudo
}

func (e *encoding) expandMessageXMD(msg []byte, n uint) []byte {
	H := crypto.Hash(e.expanderID).New()
	bLen := uint(H.Size())
	ell := (n + (bLen - 1)) / bLen
	if ell > 255 {
		panic("too big")
	}
	dstPrime := []byte{byte(len(e.DST))}
	dstPrime = append(dstPrime, e.DST...)
	zPad := make([]byte, H.BlockSize())
	libStr := []byte{0, 0}
	libStr[0] = byte((n >> 8) & 0xFF)
	libStr[1] = byte(n & 0xFF)

	H.Reset()
	_, _ = H.Write(zPad)
	_, _ = H.Write(msg)
	_, _ = H.Write(libStr)
	_, _ = H.Write([]byte{0})
	_, _ = H.Write(dstPrime)
	b0 := H.Sum(nil)

	H.Reset()
	_, _ = H.Write(b0)
	_, _ = H.Write([]byte{1})
	_, _ = H.Write(dstPrime)
	bi := H.Sum(nil)
	pseudo := append([]byte{}, bi...)
	for i := uint(2); i <= ell; i++ {
		H.Reset()
		_, _ = H.Write(xor(bi, b0))
		_, _ = H.Write([]byte{byte(i)})
		_, _ = H.Write(dstPrime)
		bi = H.Sum(nil)
		pseudo = append(pseudo, bi...)
	}
	return pseudo[0:n]
}

func xor(x, y []byte) []byte {
	for i := range x {
		x[i] ^= y[i]
	}
	return x
}

func (e *encoding) GetCurve() C.EllCurve { return e.E }
func (e *encoding) IsRandomOracle() bool { return e.RandomOracle }

type encodeToCurve struct{ *encoding }

func (s *encodeToCurve) Hash(in []byte) C.Point {
	u := s.hashToField(in, 1)
	Q := s.Mapping.Map(u[0])
	P := s.E.ClearCofactor(Q)
	return P
}

type hashToCurve struct{ *encoding }

func (s *hashToCurve) Hash(in []byte) C.Point {
	u := s.hashToField(in, 2)
	Q0 := s.Mapping.Map(u[0])
	Q1 := s.Mapping.Map(u[1])
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}
