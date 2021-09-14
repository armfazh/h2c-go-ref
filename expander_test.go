package h2c

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/armfazh/h2c-go-ref/xof"
)

type expandMsgVector struct {
	Hash    string `json:"hash"`
	Name    string `json:"name"`
	DST     string `json:"DST"`
	K       uint   `json:"k"`
	Vectors []struct {
		LenInBytes   string `json:"len_in_bytes"`
		DSTPrime     string `json:"DST_prime"`
		MsgPrime     string `json:"ms_prime"`
		UniformBytes string `json:"uniform_bytes"`
		Msg          string `json:"msg"`
	} `json:"tests"`
}

func (v expandMsgVector) test(t *testing.T) {
	var expID ExpanderDesc
	switch v.Hash {
	case "SHA256":
		expID = ExpanderDesc{XMD, uint(crypto.SHA256)}
	case "SHA512":
		expID = ExpanderDesc{XMD, uint(crypto.SHA512)}
	case "SHAKE128":
		expID = ExpanderDesc{XOF, uint(xof.SHAKE128)}
	case "SHAKE256":
		expID = ExpanderDesc{XOF, uint(xof.SHAKE256)}
	default:
		t.Fatal("Expander not supported")
	}
	exp, err := expID.Get([]byte(v.DST), v.K)
	if err != nil {
		t.Errorf(err.Error())
	}
	for i := range v.Vectors {
		len, err := strconv.ParseUint(v.Vectors[i].LenInBytes, 0, 32)
		if err != nil {
			t.Errorf(err.Error())
		}
		got := exp.Expand([]byte(v.Vectors[i].Msg), uint(len))
		want, err := hex.DecodeString(v.Vectors[i].UniformBytes)
		if err != nil {
			t.Errorf(err.Error())
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("suite: %v\ngot:  %v\nwant: %v", v.Hash, got, want)
		}
	}
}

func TestExpander(t *testing.T) {
	if errFolder := filepath.Walk("testdata/expander",
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
			var v expandMsgVector
			errJSON := json.Unmarshal(byteValue, &v)
			if errJSON != nil {
				return errJSON
			}
			t.Run(v.Name+"/"+v.Hash, v.test)
			return nil
		}); errFolder != nil {
		t.Fatalf("error on reading testdata folder: %v", errFolder)
	}
}
