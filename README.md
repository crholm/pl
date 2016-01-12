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
  -p, --pipe     Pipe key into pl

Commands:
  help [<command>...]
    Show help.

  new [<flags>] <name> [<length>]
    Register a new password.

  list
    List all password names

  show <name>
    List all password names

  copy <name> [<duration>]
    Copy passwort to clipboard

  delete <name>
    Delete a password

  git <commands>...
    Straight up git support for the password vault. git cli must be installed to be availible
```