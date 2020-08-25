package h2c

import (
	"fmt"
	"math/big"

	M "github.com/armfazh/h2c-go-ref/mapping"
	C "github.com/armfazh/tozan-ecc/curve"
	"github.com/armfazh/tozan-ecc/field"
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
	// GetHashToScalar returns a hash function that hashes strings to field elements.
	GetHashToScalar() HashToScalar
}

// HashToScalar allows to hash string into the field of scalars used for scalar multiplication.
type HashToScalar interface {
	// GetScalarField returns the field of scalars.
	GetScalarField() GF.Field
	// Hash returns an element of a field given a byte string.
	Hash(in []byte) GF.Elt
}

type fieldEncoding struct {
	F   GF.Field
	Exp Expander
	L   uint
}

func (f *fieldEncoding) GetScalarField() GF.Field { return f.F }

// Hash deterministically hashes a string msg of any length into
// an element of the given finite field.
func (f *fieldEncoding) Hash(msg []byte) GF.Elt { return f.hashToField(msg, 1)[0] }

// hashToField is a function that hashes a string msg of any length into an
// element of a finite field.
func (f *fieldEncoding) hashToField(
	msg []byte, // msg is the message to hash.
	count uint, // count is 1 or 2 (the length of the result array).
) []GF.Elt {
	m := f.F.Ext()
	length := count * m * f.L

	pseudo := f.Exp.Expand(msg, length)
	u := make([]GF.Elt, count)
	v := make([]interface{}, m)
	p := f.F.P()
	for i := uint(0); i < count; i++ {
		for j := uint(0); j < m; j++ {
			offset := f.L * (j + i*m)
			t := pseudo[offset : offset+f.L]
			vj := new(big.Int).SetBytes(t)
			v[j] = vj.Mod(vj, p)
		}
		u[i] = f.F.Elt(v)
	}
	return u
}

type encoding struct {
	E       C.EllCurve
	Mapping M.MapToCurve
	Field   *fieldEncoding
}

func (e *encoding) GetCurve() C.EllCurve { return e.E }

type encodeToCurve struct{ *encoding }

func (e *encoding) GetHashToScalar() HashToScalar {
	return &fieldEncoding{
		F:   field.NewFp(fmt.Sprintf("%v", e.E.Order()), e.E.Order()),
		Exp: e.Field.Exp,
		L:   e.Field.L,
	}
}

func (s *encodeToCurve) IsRandomOracle() bool { return false }
func (s *encodeToCurve) Hash(in []byte) C.Point {
	u := s.Field.hashToField(in, 1)
	Q := s.Mapping.Map(u[0])
	P := s.E.ClearCofactor(Q)
	return P
}

type hashToCurve struct{ *encoding }

func (s *hashToCurve) IsRandomOracle() bool { return true }
func (s *hashToCurve) Hash(in []byte) C.Point {
	u := s.Field.hashToField(in, 2)
	Q0 := s.Mapping.Map(u[0])
	Q1 := s.Mapping.Map(u[1])
	R := s.E.Add(Q0, Q1)
	P := s.E.ClearCofactor(R)
	return P
}
