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
	"github.com/zalando/go-keyring"

	"github.com/crholm/pl/vault"

	"encoding/binary"

	"sort"
	"os/exec"
	"os/user"
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

	ini		= app.Command("init", "Init your vault")

	mk 		= app.Command("mk", "Makes and save a new password.")
	mkName 		= mk.Arg("name", "Name of new password").Required().String()
	mkLength 	= mk.Arg("length", "Length of new password").Default("14").Int()
	mkNoExtra 	= mk.Flag("noextras", "Exclude specical characters from password").Short('n').Bool()

	mv 		= app.Command("mv", "Rename password")
	mvFrom 		= mv.Arg("from", "Target password to be renamed").Required().String()
	mvTo 		= mv.Arg("to", "New password name").Required().String()

	ls 		= app.Command("ls", "List all password names")

	cat 		= app.Command("cat", "Concatinates password to std out")
	catName 	= cat.Arg("name", "Name of password").Required().String()

	cp		= app.Command("cp", "Copy password to clipboard")
	cpName 		= cp.Arg("name", "Name of password").Required().String()
	cpDuration 	= cp.Arg("duration", "The number of scound the password remains in clipboard").Default("0").Int()

	rm 		= app.Command("rm", "Removes a password")
	rmName 		= rm.Arg("name", "Name of password").Required().String()

	git   		= app.Command("git", "Straight up git support for the password vault. git cli must be installed to be availible")
	gitCommands 	= git.Arg("commands", "whatever it may be").Required().Strings()

	addKey		= app.Command("add-key", "Add your vault key to systems keychain in order to avoid applying key each time")
	rmKey		= app.Command("remove-key", "Remove your vault key to systems keychain")
)

func main() {

	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	var vaultPassword string
	var m map[string]string


	if command != git.FullCommand() && command != ini.FullCommand(){
		mp, vp := readKeyAndLoad()
		if mp == nil || vp == "" {
			return
		}

		vaultPassword = vp
		m = *mp
	}



	switch  command {

	case ini.FullCommand():
		vaultPassword = readKey()
		err := vault.Init(vaultPassword)
		if(err != nil){
			fmt.Println(err)
			return
		}
		gitAddAllAndCommit("No comment =)");

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

	case cat.FullCommand():
		fmt.Println(m[*catName])

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

	case addKey.FullCommand():
		usr, err := user.Current();
		if err != nil {
			fmt.Println( err )
		}
		err2 := keyring.Set("pl", usr.Name, vaultPassword)
		if err2 != nil {
			fmt.Println(err2)
		}

		//Touching .keychain
		file := os.Getenv("HOME") + "/.pl/.keychain"
		f, err3 := os.Create(file);
		if err3 != nil {
			fmt.Println(err3)
		}else{
			f.Sync();
			f.Close();
		}

		fmt.Println("Identity added: valut key savet to key chain")

	case rmKey.FullCommand():
		usr, err := user.Current();
		if err != nil {
			fmt.Println( err )
		}

		err2 := keyring.Delete("pl", usr.Name)
		if err2 != nil {
			fmt.Println(err2)
		}

		file := os.Getenv("HOME") + "/.pl/.keychain"
		err3 := os.Remove(file);
		if err3 != nil {
			fmt.Println(err3)
		}
		fmt.Println("Identity removed: valut key removed from key chain")

	default:

	}



}

func readKey()(string){
	var vaultPassword string

	usr, err := user.Current();
	if err != nil {
		fmt.Println( err )
	}

	// key is being piped in
	if *stdin {
		r := bufio.NewReader(os.Stdin)
		passBytes, _, _ := r.ReadLine()
		vaultPassword = string(passBytes)

	// key is supplied in command line
	}else if len(*key) > 0{
		vaultPassword = *key

	// key is supplied by keychain
	}else if _, err := os.Stat(os.Getenv("HOME") + "/.pl/.keychain"); err == nil {
		passBytes, _ := keyring.Get("pl", usr.Name)
		vaultPassword = string(passBytes)

	// key is prompted for
	}else {
		fmt.Print("Enter vault key: ")
		passBytes, _ := terminal.ReadPassword(0);
		fmt.Println()
		vaultPassword = string(passBytes)
	}
	return vaultPassword;
}

func readKeyAndLoad()(*map[string]string, string){

	vaultPassword := readKey();

	mp, err := vault.Load(vaultPassword)
	if err != nil {
		fmt.Println(err)
		return nil, "";
	}

	return mp, vaultPassword
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
	var cmdOut []byte
	var err error

	dir := os.Getenv("HOME") + "/.pl"

	//Check if git is instantiated
	if !hasGit() {
		return
	}

	if cmdOut, err = exec.Command("git", "-C", dir, "push").Output(); err != nil {
		fmt.Fprintln(os.Stderr, "There was an error running git command: ", err)
		os.Exit(1)
	}
	fmt.Println(string(cmdOut))
}