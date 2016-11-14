package vault

import (
	"os"
	"io/ioutil"
	"encoding/base64"
	"crypto/sha256"
	"crypto/rand"
	"crypto/aes"
	"io"
	"crypto/cipher"
	"errors"
	"fmt"
	"encoding/json"
	"golang.org/x/crypto/scrypt"
)


type Password struct {
	Name string
	Password string
	Metadata map[string]string
}
type scryptSettings struct {
	N int //CPU
	R int //RAM
	P int //Parallelism
}

type errorVault struct {
	s string
}

func (e *errorVault) Error() string {
	return e.s
}

func hash(content []byte)([]byte){

	h := sha256.New()
	h.Write(content)

	return h.Sum(nil)
}

func SetScryptSettings(N int, r int, p int, dir string){
	scryptFile := dir + "/scrypt.conf"

	scryptData := scryptSettings{N: N, R: r, P: p}
	jsonScryptData, err := json.Marshal(scryptData)
	if err != nil {
		panic(err)
	}
	err2 := ioutil.WriteFile(scryptFile, []byte(jsonScryptData), 0644)
	check(err2)
}

func keyStretch(key string, salt []byte, dir string)([]byte){
	//The recommended parameters for interactive logins as of 2009 are N=16384, r=8, p=1

	file := dir + "/scrypt.conf"
	err1, _ := fileExists(file)
	if !err1 {
		panic(errors.New("No scrypt config exist"))
	}

	data, err2 := ioutil.ReadFile(file)
	if err2 != nil {
		panic(err2)
	}
	check(err2)

	var settings scryptSettings
	json.Unmarshal(data, &settings)


	dk, _ := scrypt.Key([]byte(key), salt, settings.N, settings.R, settings.P, 32)

	return dk;
}

func encrypt(keyString string, buf []byte, dir string)([]byte, error){

	salt, err := getSalt(dir);
	if err != nil {
		return nil, errors.New("Could not read Salt")
	}

	h := hash(buf)

	key := keyStretch(keyString, salt, dir);

	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		fmt.Println(1)
		fmt.Println(err)
		return nil, err
	}

	ciphertext := make([]byte, sha256.Size+aes.BlockSize+len(buf))

	iv := ciphertext[sha256.Size:sha256.Size+aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		fmt.Println(2)
		fmt.Println(err)
		return nil, err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[sha256.Size+aes.BlockSize:], buf)

	for i := 0; i < sha256.Size; i++{
		ciphertext[i] = h[i];
	}

	return ciphertext, nil

}
func decrypt(keyString string, buf []byte, dir string)([]byte, error){

	salt, err := getSalt(dir);
	if err != nil {
		return nil, errors.New("Could not read Salt")
	}

	key := keyStretch(keyString, salt, dir);

	block, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		return nil, err
	}
	if len(buf) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	h := buf[:sha256.Size]
	iv := buf[sha256.Size:sha256.Size+aes.BlockSize]
	buf = buf[sha256.Size+aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(buf, buf)

	if string(h) != string(hash(buf)) {
		return nil, &errorVault{"Bad Hash"}
	}

	return buf, nil

}


func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil { return true, nil }
	if os.IsNotExist(err) { return false, nil }
	return true, err
}

func Load(vaultPassword string, dir string)(*map[string]*Password, error) {

	file := dir + "/default.vault"



	os.MkdirAll(dir, 0777)

	e, _ := fileExists(file)

	if !e {
		return nil, errors.New("No vault exist")
	}


	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	check(err)

	//Decoding from base64
	b, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	//Decrypt here =)
	dec, err := decrypt(vaultPassword, b, dir)
	if err != nil {
		return nil, err
	}


	if err != nil {
		return nil, err
	}

	var m map[string]*Password



	json.Unmarshal(dec, &m)

	return &m, nil
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Init(vaultPassword string, dir string)(error){

	vaultFile := dir + "/default.vault"
	saltFile := dir + "/vault.salt"
	scryptFile := dir + "/scrypt.conf"

	b, _:= fileExists(vaultFile)
	if( b ){
		return errors.New("A vault already exist")
	}
	b, _ = fileExists(saltFile)
	if( b ){
		return errors.New("A salt already exist")
	}
	b, _ = fileExists(scryptFile)
	if( b ){
		return errors.New("A scrypt setting already exist")
	}

	os.MkdirAll(dir, 0777)

	salt := make([]byte, 32);
	io.ReadFull(rand.Reader, salt);
	sSalt := base64.StdEncoding.EncodeToString(salt)

	err1 := ioutil.WriteFile(saltFile, []byte(sSalt), 0644)
	check(err1)

	SetScryptSettings(16384, 8, 2, dir)

	m := make(map[string]*Password)

	Save(vaultPassword, &m, dir);

	return nil
}

func getSalt(dir string)([]byte, error){
	file := dir + "/vault.salt"
	e, _ := fileExists(file)

	if !e {
		return nil, errors.New("No vault exist")
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	check(err)

	//Decoding from base64
	b, err := base64.StdEncoding.DecodeString(string(data))

	return b, err;

}

func Save(vaultPassword string, vault *map[string]*Password, dir string)(error) {


	jsonVault, err := json.Marshal(vault)
	if err != nil {
		panic(err)
	}

	//Encrypt here =)
	enc, _ := encrypt(vaultPassword, jsonVault, dir)

	//	fmt.Println("LEN " + string(len(enc)))

	//Encoding to base64
	sEnc := base64.StdEncoding.EncodeToString(enc)

	//dir := os.Getenv("HOME") + "/.pl"
	file := dir + "/default.vault"

	//Writing to file
	err1 := ioutil.WriteFile(file, []byte(sEnc), 0644)
	check(err1)

	return nil

}