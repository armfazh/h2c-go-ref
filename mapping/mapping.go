// Package mapping contains a set of functions to construct functions that take
// a field element and return a point on an elliptic curve. Certain mappings
// restrict the form of the curve or its parameters.
//
// Choosing a mapping function
//
// If the target elliptic curve is:
//  - a supersingular curve, then use either the Boneh-Franklin method (NewBF) or the Elligator 2 method for A == 0 (newWA0Ell2);
//  - a Montgomery or twisted Edwards curve, then use the Elligator 2 (NewElligator2);
//  - a Weierstrass curve, then use either the Simplified SWU (NewSSWU), even if either A or B is zero;
//  - if none of the above applies, then use the Shallue-van de Woestijne method (NewSVDW).
//
// Note: the mappings must not be used standalone, since its correct and secure
// usage is determined by each hash to curve suite.
package mapping

import (
	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

// MapToCurve maps a field element into a elliptic curve point.
type MapToCurve interface {
	Map(GF.Elt) C.Point
}

// ID is an identifier of a mapping.
type ID uint

const (
	// BF is the Boneh-Franklin method
	BF ID = iota
	// SSWU is the Simplified SWU method.
	SSWU
	// ELL2 is Elligator2 method for Montgomery curves.
	ELL2
	// EDELL2 is Elligator2 method for twisted Edwards curves.
	EDELL2
	// SVDW is Shallue-van de Woestijne method.
	SVDW
)

// Get returns a MapToCurve implementation based on ID provided. Some arguments
// can be set to nil if there are not required by the mapping.
func (id ID) Get(e C.EllCurve, z GF.Elt, sgn0 GF.Sgn0ID, iso func() C.Isogeny) MapToCurve {
	switch id {
	case BF:
		return NewBF(e)
	case SSWU:
		return NewSSWU(e, z, sgn0, iso)
	case SVDW:
		return NewSVDW(e, sgn0)
	case ELL2, EDELL2:
		return NewElligator2(e, sgn0)
	default:
		panic("Mapping not supported")
	}
}
