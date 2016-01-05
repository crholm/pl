package main

import (
	"fmt"

	"github.com/atotto/clipboard"
)


func main() {
	clipboard.WriteAll("HelloCopyBoard")
	text, _ := clipboard.ReadAll()
	fmt.Println(text)

}