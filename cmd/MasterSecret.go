package main

import (
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"

	"github.com/piligo/gmsm/sm3"
)

func HashSM3(data []byte) []byte {
	hasher := sm3.New()
	hasher.Write(data)
	sum := hasher.Sum(nil)
	return sum //hex.EncodeToString(sum)
}

func pHash(result, secret, seed []byte, hash func() hash.Hash) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)
	j := 0
	for j < len(result) {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		todo := len(b)
		if j+todo > len(result) {
			todo = len(result) - j
		}
		copy(result[j:j+todo], b)
		j += todo

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}

func MasterPRF(masterkey, finished_label, sm3Hash []byte) string {
	result := make([]byte, 48) //finished计算的校验位只有12个字节
	seed := make([]byte, 0)
	seed = append(seed, finished_label...)
	seed = append(seed, sm3Hash...)
	pHash(result, masterkey, seed, sm3.New)
	fmt.Println("result out->", hex.EncodeToString(result))
	return hex.EncodeToString(result)
}

func MasterSecret() {
	masterKeyHex := "C0FD5FC6695990D23892D56590AB7CFA9B692CA6A27C801C42D85BA297666ADEA93211385C3E9C30B9A30E4C8BBA66C3"
	pre_mastekeyhex := "01017a57183fe024794f9909061b73d2bf8bd600b0abc0d6dc6e4e11202ffe3a75b708af9488b89235161c3ef8381ad3"
	pre_masterkey, _ := hex.DecodeString(pre_mastekeyhex)
	finished_label := "master secret"
	randow := Random()
	fmt.Println("randow->", hex.EncodeToString(randow))
	prf_out := MasterPRF(pre_masterkey, []byte(finished_label), randow)
	fmt.Println("PRF Out->", prf_out)
	if masterKeyHex == strings.ToUpper(prf_out) {
		fmt.Println("verify data Ok!!!")
	} else {
		fmt.Println("verify data False!!!")
	}
}

func main() {
	MasterSecret()
}

func Random() []byte {
	ClientRandom := `403cc1b00baab1e6e5c060281a2f9f2f90ed750c709ca1f1fdeafde6247fea4d`
	ServerRandom := `07dff5f4a9c898f1e83de6f1b0fd5722e4e77cae0985e568275963f9bc1fb732`
	random := ClientRandom + ServerRandom
	random = strings.ReplaceAll(random, " ", "")
	random = strings.ReplaceAll(random, "\r", "")
	random = strings.ReplaceAll(random, "\n", "")

	fmt.Println("Random->\n", random)
	hexdata, err := hex.DecodeString(random)
	if err != nil {
		fmt.Println("DecodeString Err->", err)
		return nil
	}
	return hexdata
}
