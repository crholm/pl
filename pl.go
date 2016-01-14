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
	key 		= app.Flag("key", "The key for decrypting the password vault, if not piped into the application").Short('k').String()
	stdin 		= app.Flag("stdin", "Reads key from stdin").Short('s').Bool()

	mk 			= app.Command("mk", "Makes and save a new password.")
	mkName 		= mk.Arg("name", "Name of new password").Required().String()
	mkLength 	= mk.Arg("length", "Length of new password").Default("14").Int()
	mkNoExtra 	= mk.Flag("noextras", "Exclude specical characters from password").Short('n').Bool()

	mv 			= app.Command("mv", "Rename password")
	mvFrom 		= mv.Arg("from", "Target password to be renamed").Required().String()
	mvTo 		= mv.Arg("to", "New password name").Required().String()

	ls 			= app.Command("ls", "List all password names")

	echo		= app.Command("echo", "Echo selected password to stdout")
	echoName 	= echo.Arg("name", "Name of password").Required().String()

	cp			= app.Command("cp", "Copy password to clipboard")
	cpName 		= cp.Arg("name", "Name of password").Required().String()
	cpDuration 	= cp.Arg("duration", "The number of scound the password remains in clipboard").Default("0").Int()

	rm 			= app.Command("rm", "Removes a password")
	rmName 		= rm.Arg("name", "Name of password").Required().String()

	git   		= app.Command("git", "Straight up git support for the password vault. git cli must be installed to be availible")
	gitCommands = git.Arg("commands", "whatever it may be").Required().Strings()
)

func main() {

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var vaultPassword string
	var m map[string]string


	if command != git.FullCommand(){

		if *stdin {  // key is being piped in
			r := bufio.NewReader(os.Stdin)
			passBytes, _, _ := r.ReadLine()
			vaultPassword = string(passBytes)

		}else if len(*key) > 0{ // key is supplied in command line
			vaultPassword = *key

		}else { // key is prompted
			fmt.Print("Enter vault key: ")
			passBytes, _ := terminal.ReadPassword(0);
			fmt.Println()
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

	case mk.FullCommand():
		m[*mkName] = createPassword(*mkLength, *mkNoExtra)
		vault.Save(vaultPassword, &m)
		fmt.Println(m[*mkName])
		gitAddAllAndCommit("No comment =)");

	case mv.FullCommand():
		m[*mvTo] = m[*mvFrom]
		delete(m, string(*mvFrom))
		vault.Save(vaultPassword, &m)
		gitAddAllAndCommit("No comment =)");

	case rm.FullCommand():
		delete(m, string(*rmName))
		vault.Save(vaultPassword, &m)
		gitAddAllAndCommit("No comment =)");

	case ls.FullCommand():
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

	case echo.FullCommand():
		fmt.Println(m[*echoName])

	case cp.FullCommand():
		toClipboard(m[*cpName], *cpDuration)

	case git.FullCommand():

		var cmdOut []byte
		var err    error

		dir := os.Getenv("HOME") + "/.pl"

		cmdName := "git"
		cmdArgs := *gitCommands
		// Adding path to vault dir
		cmdArgs = append([]string{"-C",  dir }, cmdArgs...)

		// Whene cloning once vault repo, making sure it ends up as the root of vault dir
		if len(cmdArgs) > 0 && cmdArgs[0] == "clone"{
			cmdArgs = append(cmdArgs, ".")
		}

		if cmdOut, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
			fmt.Fprintln(os.Stderr, "There was an error running git command: ", err)
			os.Exit(1)
		}
		fmt.Println(string(cmdOut))


	default:

	}



}


func hasGit()(bool){
	dir := os.Getenv("HOME") + "/.pl"

	//Check if git is instantiated
	if _, err := os.Stat(dir+"/.git"); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true;
}

func gitAddAllAndCommit(message string){

	var err error

	dir := os.Getenv("HOME") + "/.pl"

	//Check if git is instantiated
	if !hasGit() {
		return
	}

	if _, err = exec.Command("git", "-C", dir, "add", "-A").Output(); err != nil {
		fmt.Fprintln(os.Stderr, "There was an error running git command: ", err)
		os.Exit(1)
	}

	if _, err = exec.Command("git", "-C", dir, "commit", "-m", message).Output(); err != nil {
		fmt.Fprintln(os.Stderr, "There was an error running git command: ", err)
		os.Exit(1)
	}

}

func gitPush(){
	var err error

	dir := os.Getenv("HOME") + "/.pl"

	//Check if git is instantiated
	if !hasGit() {
		return
	}

	if _, err = exec.Command("git", "-C", dir, "push").Output(); err != nil {
		fmt.Fprintln(os.Stderr, "There was an error running git command: ", err)
		os.Exit(1)
	}
}