# pwd locker

A small cli application for protecting once passwords

## Installation 
 
 Setting up go properly 

 # git clone ...
 
 # ./install.sh

## Help
```
usage: pl [<flags>] <command> [<args> ...]

A command-line password protection application.

Flags:
      --help     Show context-sensitive help (also try --help-long and --help-man).
  -k, --key=KEY  The key for decrypting the password vault, if not piped into the application
  -s, --stdin    Reads key from stdin

Commands:
  help [<command>...]
    Show help.

  init
    Init your vault

  mk [<flags>] <name> [<length>]
    Makes and save a new password.

  mv <from> <to>
    Rename password

  ls
    List all password names

  cat <name>
    Concatinates password to std out

  cp <name> [<duration>]
    Copy password to clipboard

  rm <name>
    Removes a password

  git <commands>...
    Straight up git support for the password vault. git cli must be installed to be availible

  add-key
    Add your vault key to systems keychain in order to avoid applying key each time

  remove-key
    Remove your vault key to systems keychain

```