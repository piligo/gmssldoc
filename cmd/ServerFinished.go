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

func srv_pHash(result, secret, seed []byte, hash func() hash.Hash) {
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

func Server_PRF(masterkey, finished_label, sm3Hash []byte) string {
	result := make([]byte, 12) //finished计算的校验位只有12个字节
	seed := make([]byte, 0)
	seed = append(seed, finished_label...)
	seed = append(seed, sm3Hash...)
	srv_pHash(result, masterkey, seed, sm3.New)
	fmt.Println("result out->", hex.EncodeToString(result))
	return hex.EncodeToString(result)
}

func ServerFinished() {
	masterKeyHex := "C0FD5FC6695990D23892D56590AB7CFA9B692CA6A27C801C42D85BA297666ADEA93211385C3E9C30B9A30E4C8BBA66C3"
	masterkey, _ := hex.DecodeString(masterKeyHex)
	finished_label := "server finished"
	skemsg := ServerHashshakeMessage()
	sm3_hash := HashSM3(skemsg)
	fmt.Println("Hash->", hex.EncodeToString(sm3_hash))

	prf_out := Server_PRF(masterkey, []byte(finished_label), sm3_hash)

	fmt.Println("PRF Out->", prf_out)
	verify_data := "b7aaba4f953bb26d5b070d52"
	if verify_data == prf_out {
		fmt.Println("verify data Ok!!!")
	} else {
		fmt.Println("verify data False!!!")
	}
}

func main() {
	ServerFinished()
}

func ServerHashshakeMessage() []byte {

	ClientHello := `
    01 00 00 60 01 01 40 3c c1 b0 0b aa b1 e6 e5 c0
    60 28 1a 2f 9f 2f 90 ed 75 0c 70 9c a1 f1 fd ea
    fd e6 24 7f ea 4d 00 00 04 e0 13 00 ff 01 00 00
    33 00 0b 00 04 03 00 01 02 00 0a 00 1e 00 1c 00
    1d 00 17 00 19 00 1c 00 1b 00 18 00 1a 00 16 00
    0e 00 0d 00 0b 00 0c 00 09 00 0a 00 23 00 00 00
    0f 00 01 01`

	ServerHello := `
    02 00 00 3e 01 01 07 df f5 f4 a9 c8 98 f1 e8 3d
    e6 f1 b0 fd 57 22 e4 e7 7c ae 09 85 e5 68 27 59
    63 f9 bc 1f b7 32 00 e0 13 00 00 16 ff 01 00 01
    00 00 0b 00 04 03 00 01 02 00 23 00 00 00 0f 00
    01 01`
	Certificate := `
    0b 00 06 a4 00 06 a1 00 02 1e 30 82 02 1a 30 82
    01 c1 a0 03 02 01 02 02 09 00 93 ec ed 1d b7 b5
    29 6d 30 0a 06 08 2a 81 1c cf 55 01 83 75 30 81
    82 31 0b 30 09 06 03 55 04 06 13 02 43 4e 31 0b
    30 09 06 03 55 04 08 0c 02 42 4a 31 10 30 0e 06
    03 55 04 07 0c 07 48 61 69 44 69 61 6e 31 25 30
    23 06 03 55 04 0a 0c 1c 42 65 69 6a 69 6e 67 20
    4a 4e 54 41 20 54 65 63 68 6e 6f 6c 6f 67 79 20
    4c 54 44 2e 31 15 30 13 06 03 55 04 0b 0c 0c 53
    4f 52 42 20 6f 66 20 54 41 53 53 31 16 30 14 06
    03 55 04 03 0c 0d 54 65 73 74 20 43 41 20 28 53
    4d 32 29 30 1e 17 0d 32 30 30 36 32 33 30 33 31
    30 34 36 5a 17 0d 32 34 30 38 30 31 30 33 31 30
    34 36 5a 30 81 86 31 0b 30 09 06 03 55 04 06 13
    02 43 4e 31 0b 30 09 06 03 55 04 08 0c 02 42 4a
    31 10 30 0e 06 03 55 04 07 0c 07 48 61 69 44 69
    61 6e 31 25 30 23 06 03 55 04 0a 0c 1c 42 65 69
    6a 69 6e 67 20 4a 4e 54 41 20 54 65 63 68 6e 6f
    6c 6f 67 79 20 4c 54 44 2e 31 15 30 13 06 03 55
    04 0b 0c 0c 42 53 52 43 20 6f 66 20 54 41 53 53
    31 1a 30 18 06 03 55 04 03 0c 11 73 65 72 76 65
    72 20 73 69 67 6e 20 28 53 4d 32 29 30 59 30 13
    06 07 2a 86 48 ce 3d 02 01 06 08 2a 81 1c cf 55
    01 82 2d 03 42 00 04 3a fd 53 33 58 4a 34 7f de
    39 ab 18 c5 1d 3b 13 70 20 02 4b 5d b1 25 22 8d
    86 74 8b 25 7f bb 73 ff ea 06 1f 0d 5f d4 ad 28
    e2 6d 29 2b 50 c0 d5 2d 93 c1 db 73 31 41 44 1a
    00 9c d1 0a d0 9a 7b a3 1a 30 18 30 09 06 03 55
    1d 13 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03
    02 06 c0 30 0a 06 08 2a 81 1c cf 55 01 83 75 03
    47 00 30 44 02 1f 49 b6 1b 3d 68 46 2b a2 d7 7c
    21 0d c3 41 33 ba 6d 85 8d 2e e8 43 ae 56 90 b5
    0f 43 d1 d2 85 02 21 00 f5 d1 b8 35 00 f8 b1 69
    46 e5 57 7f 98 89 1e 73 b0 ac 27 0f e8 ee da 85
    00 90 64 4c d4 30 fc 05 00 02 5d 30 82 02 59 30
    82 02 00 a0 03 02 01 02 02 09 00 ef 22 e3 6e 32
    51 c4 e9 30 0a 06 08 2a 81 1c cf 55 01 83 75 30
    81 82 31 0b 30 09 06 03 55 04 06 13 02 43 4e 31
    0b 30 09 06 03 55 04 08 0c 02 42 4a 31 10 30 0e
    06 03 55 04 07 0c 07 48 61 69 44 69 61 6e 31 25
    30 23 06 03 55 04 0a 0c 1c 42 65 69 6a 69 6e 67
    20 4a 4e 54 41 20 54 65 63 68 6e 6f 6c 6f 67 79
    20 4c 54 44 2e 31 15 30 13 06 03 55 04 0b 0c 0c
    53 4f 52 42 20 6f 66 20 54 41 53 53 31 16 30 14
    06 03 55 04 03 0c 0d 54 65 73 74 20 43 41 20 28
    53 4d 32 29 30 1e 17 0d 32 30 30 36 32 33 30 33
    31 30 34 36 5a 17 0d 32 34 30 38 30 31 30 33 31
    30 34 36 5a 30 81 82 31 0b 30 09 06 03 55 04 06
    13 02 43 4e 31 0b 30 09 06 03 55 04 08 0c 02 42
    4a 31 10 30 0e 06 03 55 04 07 0c 07 48 61 69 44
    69 61 6e 31 25 30 23 06 03 55 04 0a 0c 1c 42 65
    69 6a 69 6e 67 20 4a 4e 54 41 20 54 65 63 68 6e
    6f 6c 6f 67 79 20 4c 54 44 2e 31 15 30 13 06 03
    55 04 0b 0c 0c 53 4f 52 42 20 6f 66 20 54 41 53
    53 31 16 30 14 06 03 55 04 03 0c 0d 54 65 73 74
    20 43 41 20 28 53 4d 32 29 30 59 30 13 06 07 2a
    86 48 ce 3d 02 01 06 08 2a 81 1c cf 55 01 82 2d
    03 42 00 04 f1 db b0 f5 40 da 8c ba b8 01 0e d8
    28 af 66 28 8d f6 ae 81 4b 08 7f 97 30 15 6b 67
    cd 9d 90 82 fe 00 2f 76 72 e3 bb d1 1c ff 16 62
    47 f6 89 38 99 df a3 d9 f6 39 9d 7d 27 19 13 80
    ea 81 b2 89 a3 5d 30 5b 30 1d 06 03 55 1d 0e 04
    16 04 14 0e ea 3c 16 b9 49 c8 d8 96 99 47 46 2f
    f1 dd cc 2e 25 f8 ac 30 1f 06 03 55 1d 23 04 18
    30 16 80 14 0e ea 3c 16 b9 49 c8 d8 96 99 47 46
    2f f1 dd cc 2e 25 f8 ac 30 0c 06 03 55 1d 13 04
    05 30 03 01 01 ff 30 0b 06 03 55 1d 0f 04 04 03
    02 01 06 30 0a 06 08 2a 81 1c cf 55 01 83 75 03
    47 00 30 44 02 20 0c bf b0 b8 c3 93 4c 18 d9 04
    b4 bf 69 cf 21 a1 7c 5d 1c e1 f1 6b f7 e4 95 21
    98 2d b3 1c a0 72 02 20 74 d3 78 2f d3 3d 5b d7
    87 39 c0 31 ec 2d 1f 06 8b 2e 81 16 cc c1 c8 32
    d1 43 95 49 bf 7c 13 40 00 02 1d 30 82 02 19 30
    82 01 c0 a0 03 02 01 02 02 09 00 93 ec ed 1d b7
    b5 29 6e 30 0a 06 08 2a 81 1c cf 55 01 83 75 30
    81 82 31 0b 30 09 06 03 55 04 06 13 02 43 4e 31
    0b 30 09 06 03 55 04 08 0c 02 42 4a 31 10 30 0e
    06 03 55 04 07 0c 07 48 61 69 44 69 61 6e 31 25
    30 23 06 03 55 04 0a 0c 1c 42 65 69 6a 69 6e 67
    20 4a 4e 54 41 20 54 65 63 68 6e 6f 6c 6f 67 79
    20 4c 54 44 2e 31 15 30 13 06 03 55 04 0b 0c 0c
    53 4f 52 42 20 6f 66 20 54 41 53 53 31 16 30 14
    06 03 55 04 03 0c 0d 54 65 73 74 20 43 41 20 28
    53 4d 32 29 30 1e 17 0d 32 30 30 36 32 33 30 33
    31 30 34 36 5a 17 0d 32 34 30 38 30 31 30 33 31
    30 34 36 5a 30 81 85 31 0b 30 09 06 03 55 04 06
    13 02 43 4e 31 0b 30 09 06 03 55 04 08 0c 02 42
    4a 31 10 30 0e 06 03 55 04 07 0c 07 48 61 69 44
    69 61 6e 31 25 30 23 06 03 55 04 0a 0c 1c 42 65
    69 6a 69 6e 67 20 4a 4e 54 41 20 54 65 63 68 6e
    6f 6c 6f 67 79 20 4c 54 44 2e 31 15 30 13 06 03
    55 04 0b 0c 0c 42 53 52 43 20 6f 66 20 54 41 53
    53 31 19 30 17 06 03 55 04 03 0c 10 73 65 72 76
    65 72 20 65 6e 63 20 28 53 4d 32 29 30 59 30 13
    06 07 2a 86 48 ce 3d 02 01 06 08 2a 81 1c cf 55
    01 82 2d 03 42 00 04 d7 12 ff b5 d8 87 ae f6 8f
    a3 0a 80 8e c2 4c 9b a5 75 26 78 44 ce fe a2 84
    7a 22 2a 51 01 31 68 a3 ef 60 9d 87 0e 67 35 8a
    82 07 33 e2 8e 27 fd fa 3a e2 07 e8 c1 98 89 76
    49 7d 94 33 83 6c 50 a3 1a 30 18 30 09 06 03 55
    1d 13 04 02 30 00 30 0b 06 03 55 1d 0f 04 04 03
    02 03 38 30 0a 06 08 2a 81 1c cf 55 01 83 75 03
    47 00 30 44 02 20 73 95 a8 96 9b 16 34 91 8a 01
    1c f0 31 de 67 30 2b 6b d6 c7 92 90 b5 29 60 9a
    b6 85 dd 82 05 08 02 20 32 8c 1f f8 26 2c 74 6f
    46 1c bd f2 c2 b2 ff 10 8c 9e ba 90 70 d7 13 8d
    92 4c 8d d8 d1 5f 0a 47`

	ServerKeyExchange := `
    0c 00 00 4a 00 48 30 46 02 21 00 b0 4b 0a a7 23
    2a 35 43 49 a3 85 26 9e 09 63 0e f8 fd cb 79 39
    1d 2f f8 68 4c aa cd 0e 61 fd e7 02 21 00 a8 4c
    45 50 17 13 43 07 a7 08 44 b5 bf 73 ed 01 06 71
    bf fb 62 8f 9c 1b 2e 91 0a 71 f8 60 25 9c
    `
	ServerHelloDone := `0e 00 00 00`
	ClientKeyExchange := `
    10 00 00 9f 00 9d 30 81 9a 02 21 00 e8 32 de 8d
    e2 a1 87 4f bb fa ec c4 b7 31 56 a8 01 94 bf cd
    87 cd 36 95 5e 6b 72 18 da 9e bf 85 02 21 00 a4
    a2 60 2f 5f 69 5b 79 41 2d aa 8d 94 1b e4 2b 61
    57 a9 17 be 2d 79 59 fd ae d1 4f 2d 5b 5b 1d 04
    20 8f 82 60 1a 67 c5 85 46 86 ed 45 d9 51 8a 3f
    3e d5 f5 fa ee 65 84 ff 9d 89 68 ff c0 c0 cf 85
    3c 04 30 20 0c 35 f0 fe 14 fc 0e a1 b6 56 c5 31
    7a 5b 7b 60 bb c1 39 a4 26 95 50 ad 5f 82 6e d2
    f1 2c fd 54 32 22 29 1c ee 75 a6 37 b0 d5 10 cc
    e7 2e f6
    `
	CliFinished := `14 00 00 0c 1a 77 09 fc 45 d8 9f 5b 1c 8e 53 ab`
	NewSessionTicket := `
    04 00 00 a6 00 00 01 2c 00 a0 2c f0 bd bb e2 d0
    56 7c 2c e2 f7 55 f1 d0 75 4c 71 7e 2a be 9a 60
    07 51 84 7f 7b 92 43 73 41 2f f0 e8 65 43 55 c1
    f2 fb 1b ad b2 8d 13 c5 a9 2f 16 61 45 0e 77 bb
    bf 68 b3 60 16 4b 23 a9 a9 0e 60 26 3c da 87 de
    df c2 43 f6 f6 8d e0 e6 a2 f9 13 d0 0f 1b 65 8f
    73 3f 5f 03 e1 c5 53 51 10 2c 7f 8f a5 a2 8f 44
    28 bd aa aa 46 f5 54 b2 1c 19 9c df 79 98 e8 08
    fb 14 97 45 9d bc 97 9f 5e 2a a5 e6 77 09 a3 d4
    6e 31 63 8f a0 f6 aa 64 42 50 6e be 40 a3 8b ae
    4c b5 1f e3 b9 34 f6 23 b7 a6`

	hashshakeMsg := ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + CliFinished + NewSessionTicket
	hashshakeMsg = strings.ReplaceAll(hashshakeMsg, " ", "")
	hashshakeMsg = strings.ReplaceAll(hashshakeMsg, "\r", "")
	hashshakeMsg = strings.ReplaceAll(hashshakeMsg, "\n", "")

	fmt.Println("hashshakeMsg->\n", hashshakeMsg)

	hexdata, err := hex.DecodeString(hashshakeMsg)
	if err != nil {
		fmt.Println("DecodeString Err->", err)
		return nil
	}
	return hexdata
}
