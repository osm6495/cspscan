package main

import (
	"github.com/osm6495/cspscan/cmd"
)

func main() {
	err := cmd.Execute()
	if err != nil {
		panic(err)
	}
}