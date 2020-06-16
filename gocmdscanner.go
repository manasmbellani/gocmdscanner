package main

//Script used to scan the specified input YAML file for
//signature and run the scan
import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

// DELIM - Delimiter to use when parsing output via regex itself
const DELIM = "|"

// DefProtocol - default protocol to use if not specified
const DefProtocol = "http"

// DefPort - Default port to use if not specified
const DefPort = "80"

// DefRegion - Default AWS region
const DefRegion = "ap-southeast-2"

// DefProfile - Default AWS profile
const DefProfile = "default"

// Format for an Example YAML signature files
type signFileStruct struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
	} `yaml:"info"`
	Author   string `yaml:"author"`
	Severity string `yaml:"severity"`
	Checks   []struct {
		Cmd      []string `yaml:"cmd"`
		CmdDir   string   `yaml:"cmddir"`
		Notes    []string `yaml:"notes"`
		Outfile  string   `yaml:"outfile"`
		Matchers []struct {
			Type  string `yaml:"type"`
			Regex string `yaml:"regex"`
		} `yaml:"matchers"`
	} `yaml:"checks"`
}

// SIGFILEEXT - Extensions for YAML files
var SIGFILEEXT []string = []string{".yml", ".yaml"}

// Find takes a slice and looks for an element in it. If found it will
// return it's key, otherwise it will return -1 and a bool of false.
func Find(slice []string, val string) (int, bool) {
	for i, item := range slice {
		if item == val {
			return i, true
		}
	}
	return -1, false
}

// Find files that have the relevant extensions. By default, YAML is used.
func findSigFiles(filesToParse []string) []string {

	var sigFiles []string

	for _, fileToCheck := range filesToParse {
		for _, ext := range SIGFILEEXT {
			isSigFile := strings.Index(fileToCheck, ext)
			if isSigFile != -1 {
				sigFiles = append(sigFiles, fileToCheck)
				break
			}
		}
	}
	return sigFiles
}

// Parse the signature file given the struct and return the contents of YAML
// Signature file
func parseSigFile(sigFile string) signFileStruct {
	var sigFileContent signFileStruct
	yamlFile, err := ioutil.ReadFile(sigFile)
	if err != nil {
		log.Printf("yamlFile.Get err   #%v ", err)
	}
	err = yaml.Unmarshal(yamlFile, &sigFileContent)
	if err != nil {
		log.Fatalf("Unmarshal: %v", err)
	}

	return sigFileContent
}

// Execute a command to get the output, error. Command is executed when in the
// optionally specified 'cmdDir' OR it is executed with the current working dir
func execCmd(cmdToExec string, verbose bool, cmdDir string) string {
	// Get the original working directory
	owd, _ := os.Getwd()

	// Switch to the directory
	if cmdDir != "" {
		os.Chdir(cmdDir)
	}

	// Get my current working directory
	cwd, _ := os.Getwd()

	if verbose {
		log.Printf("[v] Executing cmd: %s in dir: %s\n", cmdToExec, cwd)
	}

	cmd := exec.Command("/bin/bash", "-c", cmdToExec)
	out, err := cmd.CombinedOutput()
	var outStr, errStr string
	if out == nil {
		outStr = ""
	} else {
		outStr = string(out)
	}

	if err == nil {
		errStr = ""
	} else {
		errStr = string(err.Error())
		//log.Printf("Command Error: %s\n", err)
	}

	totalOut := (outStr + "\n" + errStr)
	if verbose {
		log.Printf("[v] Output of cmd '%s':\n%s\n", cmdToExec, totalOut)
	}

	// Switch back to the original working directory
	os.Chdir(owd)

	return totalOut
}

// Function substitutes target parameters hostname, port in the command to exec
func subTargetParams(cmdToExec string, targetParams map[string]string) string {
	for k, v := range targetParams {
		paramholder := "{" + k + "}"
		cmdToExec = strings.ReplaceAll(cmdToExec, paramholder, v)
	}
	return cmdToExec
}

// Print the information about the target that has been discovered matching
// the pattern
func printDetection(sigID string, target map[string]string) {
	if target["protocol"] == "aws" {
		fmt.Println("[" + sigID + "] " + target["protocol"] + "://" + target["profile"] + ":" +
			target["region"])
	} else {
		fmt.Println("[" + sigID + "] " + target["protocol"] + "://" + target["hostname"] + ":" +
			target["port"])
	}
}

// Process the command and perform the regex output
//func parseSigFileContent(signFileStructure signFileStruct) {
//}

// Worker function parses each YAML signature file, runs relevant commands as
// present in  each file and performs the matching operation
func worker(sigFile string, target map[string]string, verbose bool,
	wg *sync.WaitGroup) {
	// Need to let the waitgroup know that the function is done at the end...
	defer wg.Done()

	// Open the signature file and parse the content
	sigFileContent := parseSigFile(sigFile)

	// ID of the signature
	sigID := sigFileContent.ID

	// First get the list of all checks to perform from file
	myChecks := sigFileContent.Checks
	for _, myCheck := range myChecks {

		// Get the commmand directory to execute this command in
		cmdDir := myCheck.CmdDir

		// Run all the commands and collect the output
		cmdsToExec := myCheck.Cmd
		cmdsOutput := ""
		for _, cmdToExec := range cmdsToExec {
			cmdsToExecSub := subTargetParams(cmdToExec, target)
			cmdsOutput = cmdsOutput + "\n" + execCmd(cmdsToExecSub, verbose,
				cmdDir)
		}

		// Are there any special notes? Write them to the output
		notes := myCheck.Notes
		if notes != nil {
			for _, note := range notes {
				cmdsOutput += "\n[!] " + note
			}
		}

		// Check if we need to store output to output file
		outfile := myCheck.Outfile
		if outfile != "" {
			// Write full command output to file
			outfile = subTargetParams(outfile, target)
			ioutil.WriteFile(outfile, []byte(cmdsOutput), 0644)

			// Let user know that we wrote results to an output file
			if verbose {
				log.Printf("[*] Wrote results to outfile: %s\n", outfile)
			}
		}

		// Determine what type of matcher was provided
		matchers := myCheck.Matchers
		for _, matcher := range matchers {
			matcherType := matcher.Type
			if strings.ToLower(matcherType) == "regex" {
				strToSearch := strings.ReplaceAll(cmdsOutput, "\n", DELIM)
				strToSearch = strings.ReplaceAll(strToSearch, "\r", DELIM)
				regex := matcher.Regex
				found, err := regexp.MatchString(regex, strToSearch)
				if err != nil {
					log.Fatalf("[-] Regex Error: %s\n", err.Error())
				}
				if found == true {
					printDetection(sigID, target)
				}
			} else {
				log.Fatalf("[-] Unknown matcher type: %s\n", matcherType)
			}
		}
	}
}

func main() {
	pathsWithSigFiles := flag.String("paths", "",
		"files/folders/file-glob patterns, containing YAML signature files")
	verbose := flag.Bool("verbose", false, "show commands as executed+output")
	limit := flag.Uint("limit", 0, "Limit number of host:port targets processed")
	flag.Parse()

	if *pathsWithSigFiles == "" {
		log.Fatalln("[-] Signature files must be provided.")
	}

	// Convert the comma-sep list of files, folders to loop through
	pathsToCheck := strings.Split(*pathsWithSigFiles, ",")

	// List of all files in the folders/files above
	var filesToParse []string

	// Loop through each path and attempt to discover all files
	for _, pathToCheck := range pathsToCheck {
		// Check if glob file-pattern provided
		if strings.Index(pathToCheck, "*") >= 0 {
			matchingPaths, _ := filepath.Glob(pathToCheck)
			for _, matchingPath := range matchingPaths {
				filesToParse = append(filesToParse, matchingPath)
			}

		} else {

			//Check if file path exists
			fi, err := os.Stat(pathToCheck)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Path: %s not found\n", pathToCheck)
			} else {
				switch mode := fi.Mode(); {

				// Add all files from the directory
				case mode.IsDir():
					filepath.Walk(pathToCheck,
						func(path string, f os.FileInfo, err error) error {
							// Determine if the path is actually a file
							fi, err := os.Stat(path)
							if fi.Mode().IsRegular() == true {

								// Add the path if it doesn't already exist to list
								// of all files
								_, found := Find(filesToParse, path)
								if !found {
									filesToParse = append(filesToParse, path)
								}
							}
							return nil
						})

				// Add a single file, if not already present
				case mode.IsRegular():

					// Add the path if it doesn't already exist to list
					// of all files
					_, found := Find(filesToParse, pathToCheck)
					if !found {
						filesToParse = append(filesToParse, pathToCheck)
					}
				}
			}
		}
	}

	// Get all the Yaml files
	sigFiles := findSigFiles(filesToParse)

	// Prepare a wait group for concurrent processing of files
	var wg sync.WaitGroup

	// Count number of targets read
	var numTargetsRead uint

	// Read each target info line by line
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		numTargetsRead++

		// Read the hostname/ip address and port from user
		line := scanner.Text()
		if line != "" {
			lineSplits := strings.Split(line, ":")

			target := make(map[string]string)

			if len(lineSplits) == 1 {

				target["protocol"] = DefProtocol
				if target["protocol"] == "aws" {
					// Input provided: <hostname|aws_profile>
					// A Profile is provided if aws is the default protocol
					target["profile"] = lineSplits[0]
					target["region"] = DefProfile
				} else {
					// Only hostname is provided
					target["hostname"] = lineSplits[0]
					target["port"] = DefPort
				}
			} else if len(lineSplits) == 2 {
				if strings.Index(lineSplits[0], "/") >= 0 {
					// Input provided: protocol://<hostname|aws_profile>
					target["protocol"] = lineSplits[0]
					if target["protocol"] == "aws" {
						target["profile"] = strings.ReplaceAll(lineSplits[1], "/", "")
						target["region"] = DefProfile
					} else {
						target["hostname"] = strings.ReplaceAll(lineSplits[1], "/", "")
						target["port"] = DefPort
					}
				} else {
					// Input provided: <hostname|aws_profile>:<port|region>
					target["protocol"] = DefProtocol
					if target["protocol"] == "aws" {
						target["profile"] = lineSplits[0]
						target["region"] = lineSplits[1]
					} else {
						target["hostname"] = lineSplits[0]
						target["port"] = lineSplits[1]
					}
				}
			} else {
				// Input provided: protocol://<hostname|aws_profile>:<port|region>
				target["protocol"] = lineSplits[0]
				if target["protocol"] == "aws" {
					target["profile"] = strings.ReplaceAll(lineSplits[1], "/", "")
					target["region"] = lineSplits[2]
				} else {
					// Protocol, hostname, port all specified
					target["hostname"] = strings.ReplaceAll(lineSplits[1], "/", "")
					target["port"] = lineSplits[2]
				}
			}
			// Limit number of hosts/targets processed
			if *limit > 0 && numTargetsRead > *limit {
				break
			}

			// Start processing each file concurrently for the given hostname
			for _, sigFile := range sigFiles {
				wg.Add(1)
				go worker(sigFile, target, *verbose, &wg)
			}
		}
	}

	// Wait for all threads to end
	wg.Wait()
}
