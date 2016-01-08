package vault

import (

	"os"
	"fmt"
)

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil { return true, nil }
	if os.IsNotExist(err) { return false, nil }
	return true, err
}

func Load(vaultPassword string) (*map[string]string) {



	dir := os.Getenv("HOME") + "/.pl"
	file := dir + "/vault"

	var m map[string]string
	m = make(map[string]string)

	os.MkdirAll(dir, 0777)

	e, _ := fileExists(file)
	if !e {
		return &m
	}


	return nil

}

func Save(vaultPassword string, vault *map[string]string) {

	fmt.Println(vault)

}