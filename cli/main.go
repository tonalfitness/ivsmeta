package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/tonalfitness/ivsmeta"
)

func main() {
	var fileName string
	flag.StringVar(&fileName, "f", "", "ts file to read")
	flag.Parse()

	f := os.Stdin
	if fileName != "" {
		var err error
		f, err = os.Open(fileName)
		if err != nil {
			log.Fatalf("Failed open: %v", err)
		}
	}

	defer f.Close()
	rdr := bufio.NewReader(f)
	data, err := ivsmeta.Read(rdr)
	if err != nil {
		log.Printf("failed MD: %v", err)
	}
	for _, md := range data {
		fmt.Println(md)
	}
}
