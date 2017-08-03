package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	log "github.com/Sirupsen/logrus"
	"github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/lints"
	"github.com/zmap/zlint/zlint"
	"os"
	"runtime"
	"sync"
)

var ( //flags
	inPath           string
	outPath          string
	numCertThreads   int
	prettyPrint      bool
	numProcs         int
	channelSize      int
	crashIfParseFail bool
)

func init() {
	flag.StringVar(&inPath, "input-file", "", "File path for the input certificate(s).")
	flag.StringVar(&outPath, "output-file", "-", "File path for the output JSON.")
	flag.BoolVar(&prettyPrint, "list-lints-json", false, "Use this flag to print supported lints in JSON format, one per line")
	flag.IntVar(&numCertThreads, "cert-threads", 1, "Use this flag to specify the number of threads in -threads mode.  This has no effect otherwise.")
	flag.IntVar(&numProcs, "procs", 0, "Use this flag to specify the number of processes to run on.")
	flag.IntVar(&channelSize, "channel-size", 100000, "Use this flag to specify the number of values in the buffered channel.")
	flag.BoolVar(&crashIfParseFail, "fatal-parse-errors", false, "Fatally crash if a certificate cannot be parsed. Log by default.")
	flag.Parse()
}

func CustomMarshal(validation interface{}, lintResult *lints.ZLintResult, raw []byte, parsed *x509.Certificate) ([]byte, error) {
	return json.Marshal(struct {
		Raw        []byte             `json:"raw,omitempty"`
		Parsed     *x509.Certificate  `json:"parsed,omitempty"`
		ZLint      *lints.ZLintResult `json:"zlint,omitempty"`
		Validation interface{}        `json:"validation,omitempty"`
	}{
		Raw:        raw,
		Parsed:     parsed,
		ZLint:      lintResult,
		Validation: validation,
	})
}

func ProcessCertificate(in <-chan []byte, out chan<- []byte, wg *sync.WaitGroup) {
	log.Info("Processing certificates...")
	defer wg.Done()
	for raw := range in {
		var zdbDataInterface interface{}
		err := json.Unmarshal(raw, &zdbDataInterface)
		if err != nil {
			//Handle error
		}
		zdbData := zdbDataInterface.(map[string]interface{})
		raw := zdbData["raw"]
		validation := zdbData["validation"]
		der, err := base64.StdEncoding.DecodeString(raw.(string))
		parsed, err := x509.ParseCertificate(der)
		if err != nil { //could not parse
			if crashIfParseFail {
				log.Fatal("could not parse certificate with error: ", err)
			} else {
				log.Info("could not parse certificate with error: ", err)
			}
		} else { //parsed
			zlintResult := zlint.ZLintResultTestHandler(parsed)
			jsonResult, err := CustomMarshal(validation, zlintResult, der, parsed)
			if err != nil {
				log.Fatal("could not parse JSON.")
			}
			out <- jsonResult
		}
	} //
}

func ReadCertificate(out chan<- []byte, filename string, wg *sync.WaitGroup) {
	log.Info("Reading certificates...")
	defer wg.Done()
	if file, err := os.Open(filename); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			out <- scanner.Bytes()
		}
		if err = scanner.Err(); err != nil {
			log.Fatal("Error with scanning file: ", err)
		}
	} else {
		log.Fatal("Error reading file: ", err)
	}
}

func WriteOutput(in <-chan []byte, outputFileName string, wg *sync.WaitGroup) {
	defer wg.Done()
	var outFile *os.File
	var err error
	if outputFileName == "" || outputFileName == "-" {
		outFile = os.Stdout
	} else {
		outFile, err = os.Create(outputFileName)
		if err != nil {
			log.Fatal("Unable to create output file: ", err)
		}
		defer outFile.Close()
	}
	//
	for json := range in {
		outFile.Write(json)
		outFile.Write([]byte{'\n'})
	}
}

func main() {
	log.SetLevel(log.InfoLevel)
	runtime.GOMAXPROCS(numProcs)

	if prettyPrint {
		zlint.PrettyPrintZLint()
		return
	}

	//Initialize Channels
	certs := make(chan []byte, channelSize)
	jsonOut := make(chan []byte, channelSize)

	var readerWG sync.WaitGroup
	var procWG sync.WaitGroup
	var writerWG sync.WaitGroup

	readerWG.Add(1)
	writerWG.Add(1)

	go ReadCertificate(certs, inPath, &readerWG)
	go WriteOutput(jsonOut, outPath, &writerWG)

	for i := 0; i < numCertThreads; i++ {
		procWG.Add(1)
		go ProcessCertificate(certs, jsonOut, &procWG)
	}

	go func() {
		readerWG.Wait()
		close(certs)
	}()

	procWG.Wait()
	close(jsonOut)
	writerWG.Wait()
}
