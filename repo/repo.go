package repo

import (
	"net/http"
	"io/ioutil"
	"fmt"
	"encoding/json"
	"bufio"
	"os"
	"bytes"
	"strings"
	"github.com/crholm/pl/vault"
)

type Repo struct {
	Url string `json:"url"`
	Email string `json:"email"`
	VaultName string `json:"vaultName"`
}

type OTP struct{
	Email string `json:"email"`
	Timestamp int64 `json:"timestamp"`
	Nonce string `json:"nonce"`
	Mac string `json:"mac"`
	OTP string `json:"otp"`
}

type VaultFile struct {
	Vault string `json:"vault"`
	Salt string `json:"salt"`
	KDF vault.ScryptSettings `json:"kdf"`
}



func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil { return true, nil }
	if os.IsNotExist(err) { return false, nil }
	return true, err
}

func Load(dir string) (*Repo){
	file := dir + "/.remote"

	os.MkdirAll(dir, 0777)

	e, _ := fileExists(file)

	if !e {
		fmt.Println("Could not load vault")
		return nil
	}

	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	repo := new(Repo)
	json.Unmarshal(data, &repo);
	return repo
}


func (remote Repo) Push(dir string){

	vaultFile := dir + "/vault"
	saltFile := dir + "/salt"
	scryptFile := dir + "/scrypt"


	e, _ := fileExists(vaultFile)
	if !e {
		fmt.Println("Could not load vault")
		return
	}
	e, _ = fileExists(saltFile)
	if !e {
		fmt.Println("Could not load salt")
		return
	}
	e, _ = fileExists(scryptFile)
	if !e {
		fmt.Println("Could not load scrypt")
		return
	}

	v := new(VaultFile)

	b, err1 := ioutil.ReadFile(vaultFile)
	if err1 != nil {
		fmt.Println("Could not read vault")
		return
	}
	v.Vault = string(b)

	b, err2 := ioutil.ReadFile(saltFile)
	if err2 != nil {
		fmt.Println("Could not read salt")
		return
	}
	v.Salt = string(b)

	b, err3 := ioutil.ReadFile(scryptFile)
	if err3 != nil {
		fmt.Println("Could not read scrypt")
		return
	}

	json.Unmarshal(b, &v.KDF)

	jsonVaultFile, _ := json.Marshal(v)
	req, err1 := http.Post( remote.Url + "/vaults/" + remote.VaultName, "application/json", bytes.NewReader(jsonVaultFile));
	if err1 != nil {
		fmt.Println("Error, push vault")
		return
	}
	defer req.Body.Close()
	fmt.Println("Valut has been pushed")

}
func (remote Repo) Pull(dir string){


	vaultFileName := dir + "/vault"
	saltFileName := dir + "/salt"
	scryptFileName := dir + "/scrypt"



	req, err0 := http.Get( remote.Url + "/vaults/" + remote.VaultName);
	if err0 != nil {
		fmt.Println("Error, Pulll vault")
		return
	}
	defer req.Body.Close()
	body, err1 := ioutil.ReadAll(req.Body)
	if err1 != nil {
		fmt.Println("Error, could not add remote, stage 1")
		return
	}

	v := new(VaultFile)
	json.Unmarshal(body, &v);

	err2 := ioutil.WriteFile(vaultFileName, []byte(v.Vault), 644)
	if err2 != nil {
		fmt.Println("Could not write vault")
		return
	}

	err3 := ioutil.WriteFile(saltFileName, []byte(v.Salt), 644)
	if err3 != nil {
		fmt.Println("Could not write salt")
		return
	}

	jsonKdf, _:= json.Marshal(v.KDF);
	err4 := ioutil.WriteFile(scryptFileName, jsonKdf, 644)
	if err4 != nil {
		fmt.Println("Could not write scrypt")
		return
	}

	fmt.Println("Current vault from repo has been pulled")

}



func (remote Repo) SetRemote(dir string){

	// Requesting OTP to add remote
	reqLink, err0 := http.Post( remote.Url + "/" + remote.Email, "text/html", nil);
	if err0 != nil {
		fmt.Println("Error, could not add remote, stage 0")
		return
	}
	defer reqLink.Body.Close()
	body, err1 := ioutil.ReadAll(reqLink.Body)
	if err1 != nil {
		fmt.Println("Error, could not add remote, stage 1")
		return
	}

	// Adding OTP to response
	otp := new(OTP)
	json.Unmarshal(body, &otp);

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("An OTP has been sent to your email to verify your account")
	fmt.Print("Enter OTP: ")
	otp.OTP, _ = reader.ReadString('\n')
	otp.OTP = strings.TrimSpace(otp.OTP)

	// Sending OTP to to finish authenticating
	jsonOtp, err2 := json.Marshal(otp)
	if err2 != nil {
		fmt.Println("Error, could not add remote, stage 2")
		return
	}
	doLink, err3 := http.Post( remote.Url + "/" + remote.Email + "/link", "application/json", bytes.NewReader(jsonOtp));
	if err3 != nil {
		fmt.Println("Error, could not add remote, stage 3")
		return
	}
	defer doLink.Body.Close()
	body2, err4 := ioutil.ReadAll(doLink.Body)
	if err4 != nil {
		fmt.Println("Error, could not add remote, stage 4")
		return
	}

	// Persisting vault remote name in order to use for storage
	json.Unmarshal(body2, &remote);
	if(len(remote.VaultName) < 40){
		fmt.Println(string(body2))
		return
	}

	jsonRemote, err5 := json.Marshal(remote)
	if err5 != nil {
		fmt.Println("Error, could not add remote, stage 5")
		return
	}
	file := dir + "/.remote"

	//Writing to file
	err6 := ioutil.WriteFile(file, jsonRemote, 0644)
	if err6 != nil {
		panic(err6)
	}

}

