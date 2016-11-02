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
	"bytes"
)

func toClipboard(password string, secondsInClipboard int) {
	clipboard.WriteAll(password)

	if (secondsInClipboard > 0) {
		time.Sleep(time.Duration(secondsInClipboard) * time.Second)
		clip, _ := clipboard.ReadAll()
		if password == clip {
			clipboard.WriteAll("")
		}
	}
}

func createPassword(name string, pwdLen int, noExtras bool) (*vault.Password) {

	a := "0123456789"
	a += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	a += "abcdefghijklmnopqrstuvwxyz"

	if (!noExtras) {
		a += "<>|!#%&/()=+-_.:,;'*@${[]}\\ "
	}

	aLen := uint64(len(a))

	buf := ""
	for i := 0; i < pwdLen; i++ {
		b := make([]byte, 8)
		rand.Read(b)
		c := binary.BigEndian.Uint64(b)
		buf += string(a[c % aLen])
	}

	pwd := vault.Password{Name: name, Password:buf};


	return &pwd
}

var (
	dir string
	app = kingpin.New("pl", "A command-line password protection application.").Author("Rasmus Holm")
	key = app.Flag("key", "The key for decrypting the password vault, if not piped into the application").Short('k').String()
	path = app.Flag("path", "Path to key vault, if deault location is not desired ($HOME/.pl)").Short('p').String()
	stdin = app.Flag("stdin", "Reads key from stdin").Short('s').Bool()

	ini = app.Command("init", "Init your vault")

	mk = app.Command("mk", "Makes and save a new password.")
	mkName = mk.Arg("name", "Name of new password").Required().String()
	mkLength = mk.Arg("length", "Length of new password").Default("14").Int()
	mkNoExtra = mk.Flag("noextras", "Exclude specical characters from password").Short('n').Bool()

	set = app.Command("set", "Saves a new password.")
	setName = set.Arg("name", "Name of new password").Required().String()
	setPassword = set.Arg("password", "The passowrd itself").String()

	setMetadata = app.Command("set-metadata", "Alter metadata for password")
	setMetadataPassword = setMetadata.Arg("name", "Name of password").Required().String()
	setMetadataKey = setMetadata.Arg("key", "metadata key").Required().String()
	setMetadataValue = setMetadata.Arg("value", "metadata value").Required().String()

	rmMetadata = app.Command("rm-metadata", "Remove metadata for password")
	rmMetadataPassword = rmMetadata.Arg("name", "Name of password").Required().String()
	rmMetadataKey = rmMetadata.Arg("key", "metadata key").Required().String()

	mv = app.Command("mv", "Rename password")
	mvFrom = mv.Arg("from", "Target password to be renamed").Required().String()
	mvTo = mv.Arg("to", "New password name").Required().String()

	ls = app.Command("ls", "List all password names")
	ll = app.Command("ll", "List all password names and metadata")

	cat = app.Command("cat", "Concatinates password to std out")
	catName = cat.Arg("name", "Name of password").Required().String()

	cp = app.Command("cp", "Copy password to clipboard")
	cpName = cp.Arg("name", "Name of password").Required().String()
	cpDuration = cp.Arg("duration", "The number of scound the password remains in clipboard").Default("0").Int()

	rm = app.Command("rm", "Removes a password")
	rmName = rm.Arg("name", "Name of password").Required().String()

	git = app.Command("git", "Straight up git support for the password vault. git cli must be installed to be availible")
	gitCommands = git.Arg("commands", "whatever it may be").Required().Strings()

	addKey = app.Command("add-key", "Add your vault key to systems keychain in order to avoid applying key each time")
	rmKey = app.Command("remove-key", "Remove your vault key to systems keychain")
)

func main() {

	var command string;
	if(len(os.Args) > 1 && os.Args[1] == "git"){
		command = "git"
	}else{
		command = kingpin.MustParse(app.Parse(os.Args[1:]))

	}
	if(len(*path) > 0){
		dir = *path
	}else{
		dir = os.Getenv("HOME") + "/.pl"
	}

	var vaultPassword string
	var m map[string]*vault.Password

	if command != git.FullCommand() && command != ini.FullCommand() {
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
		err := vault.Init(vaultPassword, dir)
		if (err != nil) {
			fmt.Println(err)
			return
		}
		gitAddAllAndCommit("No-comment");

	case mk.FullCommand():
		m[*mkName] = createPassword(*mkName, *mkLength, *mkNoExtra)
		vault.Save(vaultPassword, &m, dir)
		fmt.Println(*mkName + ": " + m[*mkName].Password)
		gitAddAllAndCommit("No comment =)");

	case set.FullCommand():
		len := uint64(len(*setPassword))
		if (len == 0) {
			fmt.Print("Enter " + *setName + " Password: ")
			passBytes, _ := terminal.ReadPassword(0);

			*setPassword = string(passBytes)
		}

		pass, ok := m["route"]
		if (ok) {
			pass.Password = *setPassword
		} else {
			m[*setName] = &vault.Password{Name: *setName, Password: *setPassword}
		}

		vault.Save(vaultPassword, &m, dir)
		fmt.Println(*setName)
		gitAddAllAndCommit("No-comment");

	case mv.FullCommand():
		from, ok := m[*mvFrom]
		if(ok){
			m[*mvTo] = from
			m[*mvTo].Name = *mvTo
			delete(m, string(*mvFrom))
			vault.Save(vaultPassword, &m, dir)
			gitAddAllAndCommit("No-comment");
		}else{
			fmt.Println(*mvFrom + " does not exist")
		}


	case rm.FullCommand():
		delete(m, string(*rmName))
		vault.Save(vaultPassword, &m, dir)
		gitAddAllAndCommit("No-comment");

	case ls.FullCommand():
		l := len(m)
		arr := make([]string, l)
		i := 0
		for k, _ := range m {
			arr[i] = k
			i++
		}
		sort.Strings(arr)
		for _, v := range arr {
			fmt.Println(v)
		}
	case ll.FullCommand():
		l := len(m)
		arr := make([]string, l)
		i := 0
		for k, _ := range m {
			arr[i] = k
			i++
		}
		sort.Strings(arr)
		for _, v := range arr {
			fmt.Println(v)

			l2 := len(m[v].Metadata)
			arr2 := make([]string, l2)
			j := 0
			for k2, _ := range m[v].Metadata {
				arr2[j] = k2
				j++
			}
			for _, v2 := range arr2 {
				fmt.Println( "  " +v2 + ": " + m[v].Metadata[v2])
			}
		}


	case cat.FullCommand():
		data, ok := m[*catName]
		if(ok) {
			fmt.Println(data.Password)
		}else {
			fmt.Println(*catName + " does not exist")
		}

	case cp.FullCommand():
		data, ok := m[*cpName]
		if(ok) {
			toClipboard(data.Password, *cpDuration)
		}else {
			fmt.Println(*cpName + " does not exist")
		}

	case setMetadata.FullCommand():
		metadata, ok := m[*setMetadataPassword]
		if(ok){
			if(metadata.Metadata == nil){
				metadata.Metadata = make(map[string]string)
			}
			metadata.Metadata[*setMetadataKey] = *setMetadataValue;
			vault.Save(vaultPassword, &m, dir)
		}else{
			fmt.Println(*setMetadataPassword + " does not exist")
			return
		}

	case rmMetadata.FullCommand():
		delete(m[*rmMetadataPassword].Metadata, string(*rmMetadataKey))
		vault.Save(vaultPassword, &m, dir)
		gitAddAllAndCommit("No comment =)");


	case git.FullCommand():
		var out bytes.Buffer
		var stderr bytes.Buffer

		cmdName := "git"
		cmdArgs := os.Args[2:]

		// Adding path to vault dir
		cmdArgs = append([]string{"-C", dir }, cmdArgs...)

		// Whene cloning once vault repo, making sure it ends up as the root of vault dir
		if len(cmdArgs) > 0 && cmdArgs[0] == "clone" {
			cmdArgs = append(cmdArgs, ".")
		}

		cmd := exec.Command(cmdName, cmdArgs...)
		cmd.Stdout = &out
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			fmt.Println(fmt.Sprint(err))
			fmt.Println(stderr.String())
			os.Exit(1)
		}
		fmt.Println(out.String())

	case addKey.FullCommand():

		err2 := keyring.Set("pl", dir, vaultPassword)
		if err2 != nil {
			fmt.Println(err2)
		}

		//Touching .keychain
		file := dir + "/.keychain"
		f, err3 := os.Create(file);
		if err3 != nil {
			fmt.Println(err3)
		} else {
			f.Sync();
			f.Close();
		}
		fmt.Println("Identity added: valut key savet to key chain")

	case rmKey.FullCommand():

		err2 := keyring.Delete("pl", dir)
		if err2 != nil {
			fmt.Println(err2)
		}

		file := dir + "/.keychain"
		err3 := os.Remove(file);
		if err3 != nil {
			fmt.Println(err3)
		}
		fmt.Println("Identity removed: valut key removed from key chain")

	default:

	}
}

func readKey() (string) {
	var vaultPassword string

	// key is being piped in
	if *stdin {
		r := bufio.NewReader(os.Stdin)
		passBytes, _, _ := r.ReadLine()
		vaultPassword = string(passBytes)

		// key is supplied in command line
	} else if len(*key) > 0 {
		vaultPassword = *key

	// key is supplied by keychain
	}else if _, err := os.Stat(dir + "/.keychain"); err == nil {
		passBytes, _ := keyring.Get("pl", dir)
		vaultPassword = string(passBytes)

		// key is prompted for
	} else {
		fmt.Print("Enter vault key: ")
		passBytes, _ := terminal.ReadPassword(0);
		fmt.Println()
		vaultPassword = string(passBytes)
	}
	return vaultPassword;
}

func readKeyAndLoad() (*map[string]*vault.Password, string) {

	vaultPassword := readKey();

	mp, err := vault.Load(vaultPassword, dir)
	if err != nil {
		fmt.Println(err)
		return nil, "";
	}

	return mp, vaultPassword
}

func hasGit() (bool) {

	//Check if git is instantiated
	if _, err := os.Stat(dir + "/.git"); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true;
}

func gitAddAllAndCommit(message string) {

	var err error

	//Check if git is instantiated
	if !hasGit() {
		return
	}

	if _, err = exec.Command("git", "-C", dir, "add", "default.vault", "vault.salt").Output(); err != nil {
		fmt.Fprintln(os.Stderr, "1 There was an error running git command: ", err)
		os.Exit(1)
	}

	if _, err = exec.Command("git", "-C", dir, "commit", "-m", message).Output(); err != nil {
		fmt.Fprintln(os.Stderr, "2 There was an error running git command: ", err)
		os.Exit(1)
	}

}

func gitPush() {
	var cmdOut []byte
	var err error

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