package main

import (
	"fmt"
	"os"
	"time"
	"bufio"

	"crypto/rand"
	"golang.org/x/crypto/ssh/terminal"

	"github.com/atotto/clipboard"
	"gopkg.in/alecthomas/kingpin.v2"

	"github.com/crholm/pl/vault"

	"encoding/binary"

	"sort"
	"os/exec"
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
	app     	= kingpin.New("pl", "A command-line password protection application.").Author("Rasmus Holm")
//	app.Author("Rasmus Holm")
	key 		= app.Flag("key", "The key for decrypting the password vault, if not piped into the application").Short('k').String()
	pipe		= app.Flag("pipe", "Pipe key into pl").Short('p').Bool()

	new     	= app.Command("new", "Register a new password.")
	newName 	= new.Arg("name", "Name of new password").Required().String()
	newLength 	= new.Arg("length", "Length of new password").Default("14").Int()
	newNoExtra 	= new.Flag("noextras", "Exclude specical characters from password").Short('n').Bool()

	list     	= app.Command("list", "List all password names")

	show     	= app.Command("show", "List all password names")
	showName 	= show.Arg("name", "Name of password").Required().String()

	copy     	= app.Command("copy", "Copy password to clipboard")
	copyName 	= copy.Arg("name", "Name of password").Required().String()
	copyDuration 	= copy.Arg("duration", "The number of scound the password remains in clipboard").Default("0").Int()

	deleteCmd   	= app.Command("delete", "Delete a password")
	deleteName 	= deleteCmd.Arg("name", "Name of password").Required().String()

	git   		= app.Command("git", "Straight up git support for the password vault. git cli must be installed to be availible")
	gitCommands 	= git.Arg("commands", "whatever it may be").Required().Strings()
)

func main() {

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var vaultPassword string
	var m map[string]string


	if command != git.FullCommand(){

		if *pipe {  // key is being piped in
			r := bufio.NewReader(os.Stdin)
			passBytes, _, _ := r.ReadLine()
			vaultPassword = string(passBytes)

		}else if len(*key) > 0{ // key is supplied in command line
			vaultPassword = *key

		}else { // key is prompted
			fmt.Print("Enter vault key: ")
			passBytes, _ := terminal.ReadPassword(0);
			vaultPassword = string(passBytes)
		}

		mp, err := vault.Load(vaultPassword)
		if err != nil {
			fmt.Println("Could not open password vault")
			return;
		}
		m = *mp
	}




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

	case git.FullCommand():

		var (
			cmdOut []byte
			err    error
		)

		dir := os.Getenv("HOME") + "/.pl"

		cmdName := "git"
		cmdArgs := *gitCommands
		// Adding path to vault dir
		cmdArgs = append([]string{"-C",  dir }, cmdArgs...)

		// Whene cloning once vault repo, making sure it ends up as the root of vault dir
		if len(cmdArgs) > 0 && cmdArgs[0] == "clone"{
			cmdArgs = append(cmdArgs, ".")
		}

		fmt.Println(cmdArgs)
		if cmdOut, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
			fmt.Fprintln(os.Stderr, "There was an error running git command: ", err)
			os.Exit(1)
		}
		fmt.Println(string(cmdOut))


	default:

	}


}