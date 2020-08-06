package h2c

import (
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
	// Hash returns a point on an elliptic curve given a byte string.
	Hash(in []byte) C.Point
	// GetCurve returns the destination elliptic curve.
	GetCurve() C.EllCurve
}

// HashToScalar is an interface for hashing strings to scalars in a field.
type HashToScalar interface {
	Hash(in []byte) GF.Elt
}

type fieldEncoding struct {
	F   GF.Field
	Exp Expander
	L   uint
}

// Hash deterministically hashes a string msg of any length into
// an element of the given finite field.
func (f *fieldEncoding) Hash(msg []byte) GF.Elt {
	return hashToField(msg, 1, f.F, f.Exp, f.L)[0]
}

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func hashToField(
	msg []byte, // msg is the message to hash.
	count uint, // count is 1 or 2 (the length of the result array).
	field GF.Field, // field is the field to map into
	expander Expander,
	L uint,
) []GF.Elt {
	m := field.Ext()
	length := count * m * L

	pseudo := expander.Expand(msg, length)
	u := make([]GF.Elt, count)
	v := make([]interface{}, m)
	p := field.P()
	for i := uint(0); i < count; i++ {
		for j := uint(0); j < m; j++ {
			offset := L * (j + i*m)
			t := pseudo[offset : offset+L]
			vj := new(big.Int).SetBytes(t)
			v[j] = vj.Mod(vj, p)
		}
		u[i] = field.Elt(v)
	}
	return u
}

type encoding struct {
	E       C.EllCurve
	Exp     Expander
	Mapping M.MapToCurve
	L       uint
}

func (e *encoding) GetCurve() C.EllCurve { return e.E }

type encodeToCurve struct{ *encoding }

func (s *encodeToCurve) IsRandomOracle() bool { return false }
func (s *encodeToCurve) Hash(in []byte) C.Point {
	u := hashToField(in, 1, s.E.Field(), s.Exp, s.L)
	Q := s.Mapping.Map(u[0])
	P := s.E.ClearCofactor(Q)
	return P
}

type hashToCurve struct{ *encoding }

func (s *hashToCurve) IsRandomOracle() bool { return true }
func (s *hashToCurve) Hash(in []byte) C.Point {
	u := hashToField(in, 2, s.E.Field(), s.Exp, s.L)
	Q0 := s.Mapping.Map(u[0])
	Q1 := s.Mapping.Map(u[1])
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}
