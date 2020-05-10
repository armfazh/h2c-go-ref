package mapping_test

import (
	"testing"

	"github.com/armfazh/h2c-go-ref/mapping"
	C "github.com/armfazh/tozan-ecc/curve"
	"github.com/armfazh/tozan-ecc/curve/toy"
)

func TestBF(t *testing.T) {
	var curves = []toy.ID{toy.W2}
	for _, id := range curves {
		E, _, _ := id.New()
		F := E.Field()
		n := F.Order().Int64()
		m := mapping.NewBF(E)
		for i := int64(0); i < n; i++ {
			u := F.Elt(i)
			P := m.Map(u)
			if !E.IsOnCurve(P) {
				t.Fatalf("u: %v got P: %v\n", u, P)
			}
		}
	}
}

func TestEll2(t *testing.T) {
	var curves = []toy.ID{toy.M0, toy.M1, toy.E0, toy.W3}
	for _, id := range curves {
		E, _, _ := id.New()
		F := E.Field()
		n := F.Order().Int64()
		m := mapping.NewElligator2(E)
		for i := int64(0); i < n; i++ {
			u := F.Elt(i)
			P := m.Map(u)
			if !E.IsOnCurve(P) {
				t.Fatalf("u: %v got P: %v\n", u, P)
			}
		}
	}
}

func TestSVDW(t *testing.T) {
	var curves = []toy.ID{toy.W0}
	for _, id := range curves {
		E, _, _ := id.New()
		F := E.Field()
		n := F.Order().Int64()
		m := mapping.NewElligator2(E)
		for i := int64(0); i < n; i++ {
			u := F.Elt(i)
			P := m.Map(u)
			if !E.IsOnCurve(P) {
				t.Fatalf("%vu: %v\nP: %v not on curve.", m, u, P)
			}
		}

	}
}

func TestSSWU(t *testing.T) {
	var curves = []struct {
		id toy.ID
		Z  uint
	}{
		{toy.W0, 3},
		{toy.W1ISO, 3},
	}
	for _, c := range curves {
		E, _, _ := c.id.New()
		F := E.Field()
		n := F.Order().Int64()
		iso := func() C.Isogeny { return doubleIso{E} }
		Z := F.Elt(c.Z)
		for _, m := range []mapping.MapToCurve{
			mapping.NewSSWU(E, Z, nil),
			mapping.NewSSWU(E, Z, iso),
		} {
			for i := int64(0); i < n; i++ {
				u := F.Elt(i)
				P := m.Map(u)
				if !E.IsOnCurve(P) {
					t.Fatalf("u: %v got P: %v\n", u, P)
				}
			}
		}
	}
}

type doubleIso struct{ E C.EllCurve }

func (d doubleIso) Domain() C.EllCurve     { return d.E }
func (d doubleIso) Codomain() C.EllCurve   { return d.E }
func (d doubleIso) Push(p C.Point) C.Point { return d.E.Double(p) }
