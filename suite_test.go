package h2c_test

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	h2c "github.com/armfazh/h2c-go-ref"
)

type vectorSuite struct {
	SuiteID   string `json:"ciphersuite"`
	CurveName string `json:"curve"`
	DST       string `json:"dst"`
	Field     struct {
		M string `json:"m"`
		P string `json:"p"`
	} `json:"field"`
	Hash string `json:"hash"`
	Map  struct {
		Name string `json:"name"`
		Sgn0 string `json:"sgn0"`
	} `json:"map"`
	RandomOracle bool `json:"randomOracle"`
	Vectors      []struct {
		P struct {
			X string `json:"x"`
			Y string `json:"y"`
		} `json:"P"`
		Msg string `json:"msg"`
	} `json:"vectors"`
}

func (v vectorSuite) test(t *testing.T) {
	hashToCurve, err := h2c.SuiteID(v.SuiteID).Get()
	if err != nil {
		t.Skipf(err.Error())
	}
	E := hashToCurve.GetCurve()
	F := E.Field()
	for i := range v.Vectors {
		got := hashToCurve.Hash([]byte(v.Vectors[i].Msg), []byte(v.DST))
		want := E.NewPoint(
			F.Elt(v.Vectors[i].P.X),
			F.Elt(v.Vectors[i].P.Y),
		)
		if !got.IsEqual(want) {
			t.Fatalf("suite: %v\ngot:  %v\nwant: %v", v.SuiteID, got, want)
		}
	}
}

func TestVectors(t *testing.T) {
	if errFolder := filepath.Walk("testdata",
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
		h2c.P256_SHA256_SSWU_NU_,
		h2c.P256_SHA256_SSWU_RO_,
		h2c.P256_SHA256_SVDW_NU_,
		h2c.P256_SHA256_SVDW_RO_,
	} {
		b.Run(string(suite), func(b *testing.B) {
			hashToCurve, _ := suite.Get()
			for i := 0; i < b.N; i++ {
				hashToCurve.Hash(msg, dst)
			}
		})
	}
}
