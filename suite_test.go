package h2c_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	h2c "github.com/armfazh/h2c-go-ref"
	"github.com/armfazh/tozan-ecc/field"
)

type vectorSuite struct {
	SuiteID   string `json:"ciphersuite"`
	CurveName string `json:"curve"`
	DST       string `json:"dst"`
	L         string `json:"L"`
	Z         string `json:"Z"`
	Expand    string `json:"expand"`
	Field     struct {
		M string `json:"m"`
		P string `json:"p"`
	} `json:"field"`
	Hash string `json:"hash"`
	K    string `json:"k"`
	Map  struct {
		Name string `json:"name"`
	} `json:"map"`
	RandomOracle bool `json:"randomOracle"`
	Vectors      []struct {
		P struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"P"`
		Q0 struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"Q0"`
		Q1 struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"Q1"`
		Q struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"Q"`
		Msg string   `json:"msg"`
		U   []string `json:"u"`
	} `json:"vectors"`
}

func (v vectorSuite) test(t *testing.T) {
	hashToCurve, err := h2c.SuiteID(v.SuiteID).Get([]byte(v.DST))
	if err != nil {
		t.Skipf(err.Error())
	}
	hashToScalar := hashToCurve.GetHashToScalar()
	E := hashToCurve.GetCurve()
	F := E.Field()
	for i := range v.Vectors {
		var x, y []interface{}
		for _, xi := range strings.Split(v.Vectors[i].P.X, ",") {
			x = append(x, xi)
		}
		for _, yi := range strings.Split(v.Vectors[i].P.Y, ",") {
			y = append(y, yi)
		}

		got := hashToCurve.Hash([]byte(v.Vectors[i].Msg))
		want := E.NewPoint(F.Elt(x), F.Elt(y))
		if !got.IsEqual(want) {
			t.Fatalf("suite: %v\ngot:  %v\nwant: %v", v.SuiteID, got, want)
		}

		gotH2S := hashToScalar.Hash([]byte(v.Vectors[i].Msg))
		var wantH2S field.Elt // TATIANA: how do I get the "want" value here?
		if !F.AreEqual(gotH2S, wantH2S) {
			t.Fatalf("suite: %v\ngot:  %v\nwant: %v", v.SuiteID, gotH2S, wantH2S)
		}
	}
}

func TestVectors(t *testing.T) {
	if errFolder := filepath.Walk("testdata/suites",
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			jsonFile, errFile := os.Open(path)
			if errFile != nil {
				return errFile
			}
			defer jsonFile.Close()

			byteValue, errRead := ioutil.ReadAll(jsonFile)
			if errRead != nil {
				return errRead
			}
			var v vectorSuite
			errJSON := json.Unmarshal(byteValue, &v)
			if errJSON != nil {
				return errJSON
			}
			t.Run(v.SuiteID, v.test)
			return nil
		}); errFolder != nil {
		t.Fatalf("error on reading testdata folder: %v", errFolder)
	}
}

func BenchmarkSuites(b *testing.B) {
	msg := make([]byte, 256)
	dst := make([]byte, 10)
	for _, suite := range []h2c.SuiteID{
		h2c.P256_XMDSHA256_SSWU_RO_,
		h2c.Curve25519_XMDSHA512_ELL2_RO_,
		h2c.Curve448_XMDSHA512_ELL2_RO_,
	} {
		b.Run(string(suite), func(b *testing.B) {
			b.SetBytes(int64(len(msg)))
			hashToCurve, _ := suite.Get(dst)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hashToCurve.Hash(msg)
			}
		})
	}
}
