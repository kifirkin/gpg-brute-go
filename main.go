package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/schollz/progressbar/v3"
)

var (
	concurrency   *int
	wordsFilePath *string
	currentOps    uint32
	avgOps        uint32
)

func init() {
	concurrency = flag.Int("c", 4, "Number of goroutines.")
	wordsFilePath = flag.String("w", "", "Words list file path.")
}

func printUsage() {
	fmt.Println("Usage: ./gpg-brute-go -w words.txt [-c] 8 key1.asc key2.asc ")
	os.Exit(1)
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func checkKeys(keys []*crypto.Key, passphrase []byte) bool {
	result := false
	for _, key := range keys {
		_, err := key.Unlock(passphrase)
		if err != nil {
			break
		}
		result = true
	}
	atomic.AddUint32(&currentOps, 1)
	return result
}

func main() {
	flag.Parse()

	if *wordsFilePath == "" {
		fmt.Println("Please set wordlist file with flag `-w`")
		flag.PrintDefaults()
		printUsage()
	}

	keyPaths := flag.Args()

	if len(keyPaths) == 0 {
		fmt.Println("Please add key paths arguments after all flags.")
		printUsage()
	}

	var keyObjs []*crypto.Key
	for _, keyPath := range keyPaths {
		keyByte, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Fatalln("Error opening key file: ", err)
		}

		keyObj, err := crypto.NewKeyFromArmored(string(keyByte))
		if err != nil {
			log.Fatalln("Bad private key file: ", err)
		}

		keyObjs = append(keyObjs, keyObj)
	}

	wordlist, err := readLines(*wordsFilePath)
	if err != nil {
		log.Fatalln("Error reading wordlist file: ", err)
	}

	semaphore := make(chan struct{}, *concurrency)
	exit := make(chan os.Signal, 1)
	end := make(chan struct{}, 1)
	done := make(chan struct{}, 1)
	result := make(chan string, 1)

	signal.Notify(exit, syscall.SIGTERM)
	signal.Notify(exit, syscall.SIGINT)

	go func() {
		<-exit
		fmt.Println("Exiting...")
		os.Exit(0)
	}()

	start := time.Now()
	bar := progressbar.Default(int64(len(wordlist)))

MainLoop:
	for _, word := range wordlist {
		semaphore <- struct{}{}
		go func(word string) {
			defer func() {
				bar.Add(1)
				<-semaphore
			}()

			if checkKeys(keyObjs, []byte(word)) {
				result <- word
				done <- struct{}{}
			}
		}(word)

		select {
		case <-done:
			break MainLoop
		default:
		}
	}

	for i := 0; i < cap(semaphore); i++ {
		semaphore <- struct{}{}
	}

	fmt.Println("Work done!")

	select {
	case found := <-result:
		fmt.Println("Found password: ", found)
	default:
		fmt.Println("Password not found")
	}

	fmt.Println("Time took: ", time.Since(start))

	fmt.Println("Press ctrl+c to exit.")
	<-end
}
