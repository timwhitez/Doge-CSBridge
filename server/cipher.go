
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)



func Sha256(data []byte)[]byte{
	digest:=sha256.New()
	digest.Write(data)
	return digest.Sum(nil)
}


func encrypt(plaintext []byte, key []byte)(cipherText []byte,err2 error){

	// The key should be 16 bytes (AES-128), 24 bytes (AES-192) or
	// 32 bytes (AES-256)
	key = Sha256(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		//log.Panic(err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//log.Panic(err)
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key
	// because of the risk of repeat.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		//log.Fatal(err)
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext,nil
}



func decrypt(ciphertext []byte, key []byte)(rawText []byte,err2 error){
	key = Sha256(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		//log.Panic(err)
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		//log.Panic(err)
		return nil, err
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		//log.Panic(err)
		return nil, err
	}

	//err = ioutil.WriteFile("plaintext.exe", plaintext, 0777)
	//if err != nil {
	//	log.Panic(err)
	//}

	return plaintext,nil
}