package main

import (
	"fmt"
	"os"
	"time"
	"bufio"

	"crypto/rand"

	"github.com/atotto/clipboard"
	"gopkg.in/alecthomas/kingpin.v2"


	"github.com/crholm/pl/vault"

	"encoding/binary"

	"sort"
)




func toClipboard(password string, secondsInClipboard int ){
	clipboard.WriteAll(password)

	if(secondsInClipboard > 0){
		time.Sleep(time.Duration(secondsInClipboard) * time.Second)
		clip, _ := clipboard.ReadAll()
		if password == clip{
			clipboard.WriteAll("")
		}
	}
}


func createPassword(pwdLen int, noExtras bool)(string){

	a := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

	if(!noExtras){
		a += "<>|!#%&/()=+-_.:,;'*@${[]}\\ "
	}

	aLen := uint64(len(a))

	buf := ""
	for i := 0; i < pwdLen; i++{
		b := make([]byte, 8)
		rand.Read(b)
		c := binary.BigEndian.Uint64(b)
		buf += string(a[c % aLen])
	}

	return buf
}

var (
	app      = kingpin.New("pl", "A command-line password protection application.")
	key 	= app.Flag("key", "The key for decrypting the password vault, if not piped into the application").Short('k').String()

	new     = app.Command("new", "Register a new password.")
	newName = new.Arg("name", "Name of new password").Required().String()
	newLength = new.Arg("length", "Length of new password").Default("14").Int()
	newNoExtra = new.Flag("noextras", "Exclude specical characters from password").Short('n').Bool()

	list     = app.Command("list", "List all password names")

	show     = app.Command("show", "List all password names")
	showName = show.Arg("name", "Name of password").Required().String()

	copy     = app.Command("copy", "Copy passwort to clipboard")
	copyName = copy.Arg("name", "Name of password").Required().String()
	copyDuration = copy.Arg("duration", "The number of scound the password remains in clipboard").Default("0").Int()

	deleteCmd   = app.Command("delete", "Delete a password")
	deleteName = deleteCmd.Arg("name", "Name of password").Required().String()
)

func main() {

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var vaultPassword string
	if *key == "" {
		r := bufio.NewReader(os.Stdin)
		passBytes, _, _ := r.ReadLine()
		vaultPassword = string(passBytes)
	}else{
		vaultPassword = *key
	}


	mp, err := vault.Load(vaultPassword)
	if err != nil {
		fmt.Println("Could not open password vault")
		return;
	}
	m := *mp

	switch  command {

	case new.FullCommand():

		m[*newName] = createPassword(*newLength, *newNoExtra)
		vault.Save(vaultPassword, &m)
		fmt.Println(m[*newName])

	case deleteCmd.FullCommand():
		delete(m, string(*deleteName))
		vault.Save(vaultPassword, &m)

	case list.FullCommand():

		l := len(m)
		arr := make([]string, l)
		i := 0
		for k, _ := range m {
			arr[i] = k
			i++
		}
		sort.Strings(arr)
		for _,v := range arr{
			fmt.Println(v)
		}

	case show.FullCommand():
		fmt.Println(m[*showName])

	case copy.FullCommand():
		toClipboard(m[*copyName], *copyDuration)

	default:

	}


}