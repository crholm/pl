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

//	"io"
	"encoding/binary"

)




func toClipboard(password string, secondsInClipboard int ){
	clipboard.WriteAll(password)

	if(secondsInClipboard > 0){
		time.Sleep(time.Duration(secondsInClipboard) * time.Second)
		clipboard.WriteAll("")
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

	new     = app.Command("new", "Register a new password.")
	newName = new.Arg("name", "Name of new password").Required().String()
	newLength = new.Arg("length", "Length of new password").Default("14").Int()
	newNoExtra = new.Flag("noextras", "Exclude specical characters from password").Short('n').Bool()

	list     = app.Command("list", "List all password names")

	show     = app.Command("show", "List all password names")
	showName = show.Arg("name", "Name of password").Required().String()

	copy     = app.Command("copy", "Copy passwort to clipboard")
	copyName = copy.Arg("name", "Name of password").Required().String()
	copyDuration = copy.Arg("duration", "The number of scound the password remains in clipboard").Int()
)

func main() {

	r := bufio.NewReader(os.Stdin)
	passBytes, _, _ := r.ReadLine()
	vaultPassword := string(passBytes)

	m := *vault.Load(vaultPassword)


	switch kingpin.MustParse(app.Parse(os.Args[1:])) {

	case new.FullCommand():

		m[*newName] = createPassword(*newLength, *newNoExtra)
		vault.Save(vaultPassword, &m)
		fmt.Println("Password for " + *newName + ": " + m[*newName])


	case list.FullCommand():
		fmt.Println(list.FullCommand())

	case show.FullCommand():
		fmt.Println(show.FullCommand())
		fmt.Println(*showName)
	default:

	}

//
//	toClipboard(pass, 0)


	fmt.Println("------")
	fmt.Println(m)

}