package h2c

import (
	"crypto"
	_ "crypto/sha256" // To link the sha256 module
	_ "crypto/sha512" // To link the sha512 module
	"fmt"

	C "github.com/armfazh/h2c-go-ref/curve"
	M "github.com/armfazh/h2c-go-ref/mapping"
	E "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

// SuiteID is the identifier of supported hash to curve suites.
type SuiteID string

const (
	P256_SHA256_SSWU_NU_           SuiteID = "P256_XMD:SHA-256_SSWU_NU_"
	P256_SHA256_SSWU_RO_           SuiteID = "P256_XMD:SHA-256_SSWU_RO_"
	P256_SHA256_SVDW_NU_           SuiteID = "P256_XMD:SHA-256_SVDW_NU_"
	P256_SHA256_SVDW_RO_           SuiteID = "P256_XMD:SHA-256_SVDW_RO_"
	P384_SHA512_SSWU_NU_           SuiteID = "P384_XMD:SHA-512_SSWU_NU_"
	P384_SHA512_SSWU_RO_           SuiteID = "P384_XMD:SHA-512_SSWU_RO_"
	P384_SHA512_SVDW_NU_           SuiteID = "P384_XMD:SHA-512_SVDW_NU_"
	P384_SHA512_SVDW_RO_           SuiteID = "P384_XMD:SHA-512_SVDW_RO_"
	P521_SHA512_SSWU_NU_           SuiteID = "P521_XMD:SHA-512_SSWU_NU_"
	P521_SHA512_SSWU_RO_           SuiteID = "P521_XMD:SHA-512_SSWU_RO_"
	P521_SHA512_SVDW_NU_           SuiteID = "P521_XMD:SHA-512_SVDW_NU_"
	P521_SHA512_SVDW_RO_           SuiteID = "P521_XMD:SHA-512_SVDW_RO_"
	Curve25519_SHA256_ELL2_NU_     SuiteID = "curve25519_XMD:SHA-256_ELL2_NU_"
	Curve25519_SHA256_ELL2_RO_     SuiteID = "curve25519_XMD:SHA-256_ELL2_RO_"
	Curve25519_SHA512_ELL2_NU_     SuiteID = "curve25519_XMD:SHA-512_ELL2_NU_"
	Curve25519_SHA512_ELL2_RO_     SuiteID = "curve25519_XMD:SHA-512_ELL2_RO_"
	Edwards25519_SHA256_EDELL2_NU_ SuiteID = "edwards25519_XMD:SHA-256_ELL2_NU_"
	Edwards25519_SHA256_EDELL2_RO_ SuiteID = "edwards25519_XMD:SHA-256_ELL2_RO_"
	Edwards25519_SHA512_EDELL2_NU_ SuiteID = "edwards25519_XMD:SHA-512_ELL2_NU_"
	Edwards25519_SHA512_EDELL2_RO_ SuiteID = "edwards25519_XMD:SHA-512_ELL2_RO_"
	Curve448_SHA512_ELL2_NU_       SuiteID = "curve448_XMD:SHA-512_ELL2_NU_"
	Curve448_SHA512_ELL2_RO_       SuiteID = "curve448_XMD:SHA-512_ELL2_RO_"
	Edwards448_SHA512_EDELL2_NU_   SuiteID = "edwards448_XMD:SHA-512_ELL2_NU_"
	Edwards448_SHA512_EDELL2_RO_   SuiteID = "edwards448_XMD:SHA-512_ELL2_RO_"
	SECP256k1_SHA256_SSWU_NU_      SuiteID = "secp256k1_XMD:SHA-256_SSWU_NU_"
	SECP256k1_SHA256_SSWU_RO_      SuiteID = "secp256k1_XMD:SHA-256_SSWU_RO_"
	SECP256k1_SHA256_SVDW_NU_      SuiteID = "secp256k1_XMD:SHA-256_SVDW_NU_"
	SECP256k1_SHA256_SVDW_RO_      SuiteID = "secp256k1_XMD:SHA-256_SVDW_RO_"
	BLS12381G1_SHA256_SSWU_NU_     SuiteID = "BLS12381G1_XMD:SHA-256_SSWU_NU_"
	BLS12381G1_SHA256_SSWU_RO_     SuiteID = "BLS12381G1_XMD:SHA-256_SSWU_RO_"
	BLS12381G1_SHA256_SVDW_NU_     SuiteID = "BLS12381G1_XMD:SHA-256_SVDW_NU_"
	BLS12381G1_SHA256_SVDW_RO_     SuiteID = "BLS12381G1_XMD:SHA-256_SVDW_RO_"
)

// Get returns a HashToPoint based on the SuiteID, otherwise returns an error
// if the SuiteID is not supported or invalid.
func (id SuiteID) Get() (HashToPoint, error) {
	if s, ok := supportedSuitesID[id]; ok {
		E := s.E.Get()
		H := s.H.New
		Z := E.Field().Elt(s.Z)
		m := s.Map.Get(E, Z, s.Sgn0, s.Iso)
		e := &encoding{E, H, s.L, m, s.RO, XMD}
		if s.RO {
			return &hashToCurve{e}, nil
		}
		return &encodeToCurve{e}, nil
	}
	return nil, fmt.Errorf("Suite: %v not supported", id)
}

type params struct {
	ID   SuiteID
	E    C.ID
	H    crypto.Hash
	Map  M.ID
	Sgn0 GF.Sgn0ID
	L    uint
	Z    int
	Iso  func() E.Isogeny
	RO   bool
}

func (id SuiteID) register(s *params) {
	s.ID = id
	supportedSuitesID[id] = *s
}

var supportedSuitesID map[SuiteID]params

func init() {
	supportedSuitesID = make(map[SuiteID]params)
	sha256 := crypto.SHA256
	sha512 := crypto.SHA512
	P256_SHA256_SSWU_NU_.register(&params{E: C.P256, H: sha256, Map: M.SSWU, Sgn0: GF.SignLE, L: 48, RO: false, Z: -10})
	P256_SHA256_SSWU_RO_.register(&params{E: C.P256, H: sha256, Map: M.SSWU, Sgn0: GF.SignLE, L: 48, RO: true, Z: -10})
	P256_SHA256_SVDW_NU_.register(&params{E: C.P256, H: sha256, Map: M.SVDW, Sgn0: GF.SignLE, L: 48, RO: false})
	P256_SHA256_SVDW_RO_.register(&params{E: C.P256, H: sha256, Map: M.SVDW, Sgn0: GF.SignLE, L: 48, RO: true})
	P384_SHA512_SSWU_NU_.register(&params{E: C.P384, H: sha512, Map: M.SSWU, Sgn0: GF.SignLE, L: 72, RO: false, Z: -12})
	P384_SHA512_SSWU_RO_.register(&params{E: C.P384, H: sha512, Map: M.SSWU, Sgn0: GF.SignLE, L: 72, RO: true, Z: -12})
	P384_SHA512_SVDW_NU_.register(&params{E: C.P384, H: sha512, Map: M.SVDW, Sgn0: GF.SignLE, L: 72, RO: false})
	P384_SHA512_SVDW_RO_.register(&params{E: C.P384, H: sha512, Map: M.SVDW, Sgn0: GF.SignLE, L: 72, RO: true})
	P521_SHA512_SSWU_NU_.register(&params{E: C.P521, H: sha512, Map: M.SSWU, Sgn0: GF.SignLE, L: 96, RO: false, Z: -4})
	P521_SHA512_SSWU_RO_.register(&params{E: C.P521, H: sha512, Map: M.SSWU, Sgn0: GF.SignLE, L: 96, RO: true, Z: -4})
	P521_SHA512_SVDW_NU_.register(&params{E: C.P521, H: sha512, Map: M.SVDW, Sgn0: GF.SignLE, L: 96, RO: false})
	P521_SHA512_SVDW_RO_.register(&params{E: C.P521, H: sha512, Map: M.SVDW, Sgn0: GF.SignLE, L: 96, RO: true})
	Curve25519_SHA256_ELL2_NU_.register(&params{E: C.Curve25519, H: sha256, Map: M.ELL2, Sgn0: GF.SignLE, L: 48, RO: false})
	Curve25519_SHA256_ELL2_RO_.register(&params{E: C.Curve25519, H: sha256, Map: M.ELL2, Sgn0: GF.SignLE, L: 48, RO: true})
	Curve25519_SHA512_ELL2_NU_.register(&params{E: C.Curve25519, H: sha512, Map: M.ELL2, Sgn0: GF.SignLE, L: 48, RO: false})
	Curve25519_SHA512_ELL2_RO_.register(&params{E: C.Curve25519, H: sha512, Map: M.ELL2, Sgn0: GF.SignLE, L: 48, RO: true})
	Edwards25519_SHA256_EDELL2_NU_.register(&params{E: C.Edwards25519, H: sha256, Map: M.EDELL2, Sgn0: GF.SignLE, L: 48, RO: false})
	Edwards25519_SHA256_EDELL2_RO_.register(&params{E: C.Edwards25519, H: sha256, Map: M.EDELL2, Sgn0: GF.SignLE, L: 48, RO: true})
	Edwards25519_SHA512_EDELL2_NU_.register(&params{E: C.Edwards25519, H: sha512, Map: M.EDELL2, Sgn0: GF.SignLE, L: 48, RO: false})
	Edwards25519_SHA512_EDELL2_RO_.register(&params{E: C.Edwards25519, H: sha512, Map: M.EDELL2, Sgn0: GF.SignLE, L: 48, RO: true})
	Curve448_SHA512_ELL2_NU_.register(&params{E: C.Curve448, H: sha512, Map: M.ELL2, Sgn0: GF.SignLE, L: 84, RO: false})
	Curve448_SHA512_ELL2_RO_.register(&params{E: C.Curve448, H: sha512, Map: M.ELL2, Sgn0: GF.SignLE, L: 84, RO: true})
	Edwards448_SHA512_EDELL2_NU_.register(&params{E: C.Edwards448, H: sha512, Map: M.EDELL2, Sgn0: GF.SignLE, L: 84, RO: false})
	Edwards448_SHA512_EDELL2_RO_.register(&params{E: C.Edwards448, H: sha512, Map: M.EDELL2, Sgn0: GF.SignLE, L: 84, RO: true})
	SECP256k1_SHA256_SSWU_NU_.register(&params{E: C.SECP256K1, H: sha256, Map: M.SSWU, Sgn0: GF.SignLE, L: 48, RO: false, Z: -11, Iso: C.GetSECP256K1Isogeny})
	SECP256k1_SHA256_SSWU_RO_.register(&params{E: C.SECP256K1, H: sha256, Map: M.SSWU, Sgn0: GF.SignLE, L: 48, RO: true, Z: -11, Iso: C.GetSECP256K1Isogeny})
	SECP256k1_SHA256_SVDW_NU_.register(&params{E: C.SECP256K1, H: sha256, Map: M.SVDW, Sgn0: GF.SignLE, L: 48, RO: false})
	SECP256k1_SHA256_SVDW_RO_.register(&params{E: C.SECP256K1, H: sha256, Map: M.SVDW, Sgn0: GF.SignLE, L: 48, RO: true})
	BLS12381G1_SHA256_SSWU_NU_.register(&params{E: C.BLS12381G1, H: sha256, Map: M.SSWU, Sgn0: GF.SignBE, L: 64, RO: false, Z: 11, Iso: C.GetBLS12381G1Isogeny})
	BLS12381G1_SHA256_SSWU_RO_.register(&params{E: C.BLS12381G1, H: sha256, Map: M.SSWU, Sgn0: GF.SignBE, L: 64, RO: true, Z: 11, Iso: C.GetBLS12381G1Isogeny})
	BLS12381G1_SHA256_SVDW_NU_.register(&params{E: C.BLS12381G1, H: sha256, Map: M.SVDW, Sgn0: GF.SignBE, L: 64, RO: false})
	BLS12381G1_SHA256_SVDW_RO_.register(&params{E: C.BLS12381G1, H: sha256, Map: M.SVDW, Sgn0: GF.SignBE, L: 64, RO: true})
}
