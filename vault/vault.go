package vault

import (

	"os"
	//"bytes"
	//"encoding/gob"
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
)


type Password struct {
	Name string
	Password string
	Metadata map[string]string
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

func encrypt(keyString string, buf []byte)([]byte, error){

	salt, err := getSalt();
	if err != nil {
		return nil, errors.New("Could not read Salt")
	}

	h := hash(buf)

	key := hash(append([]byte(keyString), salt...))

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
func decrypt(keyString string, buf []byte)([]byte, error){

	salt, err := getSalt();
	if err != nil {
		return nil, errors.New("Could not read Salt")
	}

	key := hash(append([]byte(keyString), salt...))

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

func Load(vaultPassword string)(*map[string]*Password, error) {

	dir := os.Getenv("HOME") + "/.pl"
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
	dec, err := decrypt(vaultPassword, b)
	if err != nil {
		return nil, err
	}

	//Deserializing map
	//r := bytes.NewReader(dec)
	//d := gob.NewDecoder(r)

	//err = d.Decode(&m)

	if err != nil {
		return nil, err
	}

	var m map[string]*Password



	json.Unmarshal(dec, &m)

	//fmt.Println("JSON " + string(dec));

	return &m, nil
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func Init(vaultPassword string)(error){

	dir := os.Getenv("HOME") + "/.pl"
	vault := dir + "/default.vault"
	saltFile := dir + "/vault.salt"
	b, _:= fileExists(vault)
	if( b ){
		return errors.New("A vault already exist")
	}
	b, _ = fileExists(saltFile)
	if( b ){
		return errors.New("A salt already exist")
	}

	os.MkdirAll(dir, 0777)

	salt := make([]byte, 32);
	io.ReadFull(rand.Reader, salt);
	sSalt := base64.StdEncoding.EncodeToString(salt)

	err1 := ioutil.WriteFile(saltFile, []byte(sSalt), 0644)
	check(err1)




	m := make(map[string]*Password)

	Save(vaultPassword, &m);

	return nil
}

func getSalt()([]byte, error){
	dir := os.Getenv("HOME") + "/.pl"
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

func Save(vaultPassword string, vault *map[string]*Password)(error) {


	//Serializing
	//b := new(bytes.Buffer)
	//e := gob.NewEncoder(b)

	jsonVault, err := json.Marshal(vault)
	if err != nil {
		panic(err)
	}

	//Encrypt here =)
	enc, _ := encrypt(vaultPassword, jsonVault)

	//	fmt.Println("LEN " + string(len(enc)))

	//Encoding to base64
	sEnc := base64.StdEncoding.EncodeToString(enc)

	dir := os.Getenv("HOME") + "/.pl"
	file := dir + "/default.vault"

	//Writing to file
	err1 := ioutil.WriteFile(file, []byte(sEnc), 0644)
	check(err1)

	return nil

}