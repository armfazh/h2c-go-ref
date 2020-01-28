package h2c

import (
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/hkdf"

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
}

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func (e *encoding) hashToField(
	msg []byte, // msg is the message to hash.
	dst []byte, // DST, a domain separation tag (see discussion above).
	ctr byte, // ctr is 0, 1, or 2.
) GF.Elt {
	info := []byte{'H', '2', 'C', ctr, byte(1)}
	msgPrime := hkdf.Extract(e.HFunc, append(msg, byte(0)), dst)

	F := e.E.Field()
	m := F.Ext()
	v := make([]interface{}, m)
	t := make([]byte, e.L)

	for i := uint(1); i <= m; i++ {
		info[4] = byte(i)
		rd := hkdf.Expand(e.HFunc, msgPrime, info)
		if _, err := io.ReadFull(rd, t); err != nil {
			panic("error on hdkf")
		}
		vi := new(big.Int).SetBytes(t)
		v[i-1] = vi.Mod(vi, F.P())
	}
	return F.Elt(v)
}

func (e *encoding) GetCurve() C.EllCurve { return e.E }
func (e *encoding) IsRandomOracle() bool { return e.RandomOracle }

type encodeToCurve struct{ *encoding }

func (s *encodeToCurve) Hash(in, dst []byte) C.Point {
	u := s.hashToField(in, dst, byte(2))
	Q := s.Mapping.Map(u)
	P := s.E.ClearCofactor(Q)
	return P
}

type hashToCurve struct{ *encoding }

func (s *hashToCurve) Hash(in, dst []byte) C.Point {
	u0 := s.hashToField(in, dst, byte(0))
	u1 := s.hashToField(in, dst, byte(1))
	Q0 := s.Mapping.Map(u0)
	Q1 := s.Mapping.Map(u1)
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}
