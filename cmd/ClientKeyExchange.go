package main

//编译命令
//go build -mod=vendor cmd\ClientKeyExchange.go

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"

	"github.com/piligo/gmsm/sm2"
)

//Ans编码：SM2加密后的数据
type AnsSm2EnData struct {
	X    *big.Int
	Y    *big.Int
	Hash []byte
	Data []byte
}

//golang 使用的密文是：04+C1+C3+C2
func (ased *AnsSm2EnData) GO_C1C3C2() []byte {
	C1 := ased.X.Text(16) + ased.Y.Text(16)
	C2 := hex.EncodeToString(ased.Data)
	C3 := hex.EncodeToString(ased.Hash)

	data, _ := hex.DecodeString("04" + C1 + C3 + C2)
	return data
}

//工具使用的密文是：C1+C2+C3
func (ased *AnsSm2EnData) Tool_C1C2C3() []byte {
	C1 := ased.X.Text(16) + ased.Y.Text(16)
	C2 := hex.EncodeToString(ased.Data)
	C3 := hex.EncodeToString(ased.Hash)

	data, _ := hex.DecodeString(C1 + C2 + C3)
	return data
}

func DeCodeEnData() (*AnsSm2EnData, error) {
	data := "30819a022100e832de8de2a1874fbbfaecc4b73156a80194bfcd87cd36955e6b7218da9ebf85022100a4a2602f5f695b79412daa8d941be42b6157a917be2d7959fdaed14f2d5b5b1d04208f82601a67c5854686ed45d9518a3f3ed5f5faee6584ff9d8968ffc0c0cf853c0430200c35f0fe14fc0ea1b656c5317a5b7b60bbc139a4269550ad5f826ed2f12cfd543222291cee75a637b0d510cce72ef6"
	dataHex, _ := hex.DecodeString(data)

	var ansdata AnsSm2EnData
	_, err := asn1.Unmarshal(dataHex, &ansdata)
	if err != nil {
		fmt.Println("DeCodeEnData Unmarshal err -> ", err)
		return nil, err
	}
	fmt.Printf("X= %s \nY = %s \n", ansdata.X.Text(16), ansdata.Y.Text(16))
	fmt.Println("HASH out->", hex.EncodeToString(ansdata.Hash))
	fmt.Println("Data out->", hex.EncodeToString(ansdata.Data))
	return &ansdata, nil
}

func ClientKeyExchange() {
	//读取密钥
	raw, err := ioutil.ReadFile("sm2Certs/SE.key.pem")
	if err != nil {
		fmt.Println("ReadFile err->", err)
		return
	}
	fmt.Println("ClientKeyExchange CertPem->\n", string(raw))

	//解码密钥 实际上就是base64解码
	block, _ := pem.Decode(raw)
	// sm2 解密私钥
	prvkey, err := sm2.ParsePKCS8UnecryptedPrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("ClientKeyExchange ParsePKCS8UnecryptedPrivateKey err->", err)
		return
	}
	fmt.Printf("KEY D= %s  \n", prvkey.D.Text(16))

	endata, _ := DeCodeEnData()
	out, err := prvkey.Decrypt(endata.GO_C1C3C2())
	if err != nil {
		fmt.Println("ClientKeyExchange Decrypt err->", err)
		return
	}
	fmt.Println("------------------------------------------")
	fmt.Println("明文 ->", hex.EncodeToString(out))
	fmt.Println("--------------------tools data ----------------------")
	tdata := hex.EncodeToString(endata.Tool_C1C2C3())
	fmt.Println("TOOLS->", tdata)
}

func main() {
	ClientKeyExchange()

}
