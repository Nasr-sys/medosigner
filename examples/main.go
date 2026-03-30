package main

import (
	"fmt"
	"log"

	"github.com/Nasr-sys/medosigner"
)

func main() {
	// Example: Ladon encryption
	ladon := &medosigner.Ladon{}
	result := ladon.Encrypt(1674223203, "1611921764", 1233)
	fmt.Println("Ladon Result:", result)

	// Example: Gorgon encryption
	gorgon := medosigner.NewGorgon("param1=value1&param2=value2", 1674223203, "data", "cookies")
	headers := gorgon.GetValue()
	fmt.Println("Gorgon Headers:", headers)

	// Example: Argus encryption
	argus := &medosigner.Argus{}
	sign, err := argus.GetSign("query", "data", 0, 1233, 1611921764, 0, "", "v04.04.05-ov-android", 134744640)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Argus Sign:", sign)
}