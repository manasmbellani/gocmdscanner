package main

//Script used to scan the specified input YAML file for
//signature and run the scan
import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

// Delim - Delimiter to use when parsing output via regex itself
const Delim = "|"

// DefProtocol - default protocol to use if not specified
const DefProtocol = "http"

// DefPort - Default port to use if not specified
const DefPort = "80"

// DefRegion - Default AWS region
const DefRegion = "ap-southeast-2"

// DefProfile - Default AWS profile
const DefProfile = "default"

// DefHTTPMethod - Default HTTP Method
const DefHTTPMethod = "GET"

// DefUserAgent - Default user agent string
const DefUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"

// Format for an Example YAML signature files
type signFileStruct struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
	} `yaml:"info"`
	Author   string     `yaml:"author"`
	Severity string     `yaml:"severity"`
	Checks   []sigCheck `yaml:"checks"`
}

// Define a separate struct for checks
type sigCheck struct {
	Cmd        []string `yaml:"cmd"`
	CmdDir     string   `yaml:"cmddir"`
	URLs       []string `yaml:"url"`
	HTTPMethod string   `yaml:"method"`
	Body       []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:body`
	Headers []struct {
		Name  string `yaml:"name"`
		Value string `yaml:"value"`
	} `yaml:"headers"`
	Notes    []string `yaml:"notes"`
	Outfile  string   `yaml:"outfile"`
	Matchers []struct {
		Type  string `yaml:"type"`
		Regex string `yaml:"regex"`
	} `yaml:"matchers"`
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
// the pattern. For web detections, display additional path as well.
func formatDetection(sigID string, target map[string]string) string {

	pathToPrint := ""
	if target["protocol"] == "aws" {
		pathToPrint = "[" + sigID + "] " + target["protocol"] + "://" +
			target["profile"] + ":" + target["region"]
	} else {
		fullURLPath, fullURLPathFound := target["fullURLPath"]

		if fullURLPathFound {
			pathToPrint = fullURLPath
		} else {
			pathToPrint = "[" + sigID + "] " + target["protocol"] + "://" + target["hostname"] + ":" +
				target["port"]
		}
	}

	return pathToPrint
}

// Get given match config and search output for keywords. If found, then
func runMatch(checkConfig sigCheck, outputToSearch string) bool {
	matcherFound := false

	// Determine what type of matcher was provided
	matchers := checkConfig.Matchers
	for _, matcher := range matchers {
		matcherType := matcher.Type
		if strings.ToLower(matcherType) == "regex" {
			strToSearch := strings.ReplaceAll(outputToSearch, "\n", Delim)
			strToSearch = strings.ReplaceAll(strToSearch, "\r", Delim)
			regex := matcher.Regex
			found, err := regexp.MatchString(regex, strToSearch)
			if err != nil {
				log.Fatalf("[-] Regex Error: %s\n", err.Error())
			}
			if found == true {
				matcherFound = true
				break
			}
		} else {
			log.Fatalf("[-] Unknown matcher type: %s\n", matcherType)
		}
	}
	return matcherFound
}

// Process the command and perform the regex output
//func parseSigFileContent(signFileStructure signFileStruct) {
//}

// Worker function parses each YAML signature file, runs relevant commands as
// present in  each file and performs the matching operation
func worker(sigFileContent signFileStruct, target map[string]string, verbose bool,
	wg *sync.WaitGroup) {
	// Need to let the waitgroup know that the function is done at the end...
	defer wg.Done()

	// ID of the signature
	sigID := sigFileContent.ID

	// First get the list of all checks to perform from file
	myChecks := sigFileContent.Checks

	for _, myCheck := range myChecks {

		// Get the commmand directory to execute this command in
		cmdDir := myCheck.CmdDir

		// Store commands output

		// Run all the commands and collect output
		cmdsOutput := ""
		requestOutput := ""
		cmdsToExec := myCheck.Cmd
		for _, cmdToExec := range cmdsToExec {

			// Run the commands
			cmdsToExecSub := subTargetParams(cmdToExec, target)
			cmdsOutput = cmdsOutput + "\n" + execCmd(cmdsToExecSub, verbose,
				cmdDir)

			// Check for a match from response
			matcherFound := runMatch(myCheck, cmdsOutput)
			if matcherFound {
				fmt.Println(formatDetection(sigID, target))
			}
		}

		// Run any web requests on URLs, if provided
		urls := myCheck.URLs

		for _, urlToCheck := range urls {
			httpMethod := strings.ToUpper(myCheck.HTTPMethod)
			if httpMethod == "" {
				httpMethod = DefHTTPMethod
			}

			// Build the URL to request + save it
			urlToCheckSub := subTargetParams(urlToCheck, target)
			target["fullURLPath"] = urlToCheckSub

			// Build a HTTP request template
			client := &http.Client{}
			var body io.Reader

			// Prepare the POST body
			var strBodyParams []string
			if myCheck.Body != nil {
				for _, bodySet := range myCheck.Body {
					name := bodySet.Name
					value := bodySet.Value
					strBodyParams = append(strBodyParams, name+"="+value)
				}
			}
			strBody := strings.Join(strBodyParams, "&")
			body = strings.NewReader(strBody)

			// Setup a request template
			req, _ := http.NewRequest(httpMethod, urlToCheckSub, body)

			// Set the user agent string header
			req.Header.Set("User-Agent", DefUserAgent)

			// Set custom headers if any are provided
			if myCheck.Headers != nil {
				for _, header := range myCheck.Headers {
					name := header.Name
					value := header.Value
					req.Header.Set(name, value)
				}
			}

			// Verbose message to be printed to let the user know
			if verbose {
				log.Printf("Making %s request to URL: %s\n", httpMethod,
					urlToCheckSub)
			}

			// Send the web request
			resp, _ := client.Do(req)

			if resp != nil {

				// Read the response body
				respBody, _ := ioutil.ReadAll(resp.Body)

				// Read the response status code as string
				statusCode := fmt.Sprintf("%d", resp.StatusCode)

				// Read the response headers as string
				respHeaders := resp.Header
				respHeadersStr := ""
				s := ""
				for k, v := range respHeaders {
					s = fmt.Sprintf("%s=\"%s\"", k, strings.Join(v, ","))
					respHeadersStr += s + ";"
				}

				// Combine status code, response headers and body
				requestOutput = string(statusCode) + "\n" + respHeadersStr + "\n" +
					string(respBody)

				// Verbose message to be printed to let the user know
				if verbose {
					log.Printf("Making %s request to URL: %s\n", httpMethod,
						urlToCheckSub)
				}

				// Check for a match from the response
				matcherFound := runMatch(myCheck, requestOutput)
				if matcherFound {
					fmt.Println(formatDetection(sigID, target))
				}
			}
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

			// Get the command and web request output together to write to file
			contentToWrite := cmdsOutput + "\n" + requestOutput

			// Write output to file
			outfile = subTargetParams(outfile, target)
			ioutil.WriteFile(outfile, []byte(contentToWrite), 0644)

			// Let user know that we wrote results to an output file
			if verbose {
				log.Printf("[*] Wrote results to outfile: %s\n", outfile)
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

	// parse information from each signature file and store it so it doesn't
	// have to be read again & again
	sigFileContents := make(map[string]signFileStruct, len(sigFiles))
	for _, sigFile := range sigFiles {
		sigFileContents[sigFile] = parseSigFile(sigFile)
	}

	// Prepare a wait group for concurrent processing of files
	var wg sync.WaitGroup

	// Count number of targets read
	var numTargetsRead uint

	// Read each target info line by line
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		numTargetsRead++

		// Read the hostname/ip address, port OR URL paths from user
		line := scanner.Text()
		if line != "" {
			// Split based on: for hostname & port OR protocol & hostname & port
			// specified
			lineSplits := strings.Split(line, ":")

			target := make(map[string]string)

			if len(lineSplits) == 1 {

				target["protocol"] = DefProtocol
				if target["protocol"] == "aws" {
					// Input provided: <hostname|aws_profile>/<path>
					// A Profile is provided if aws is the default protocol
					target["profile"] = lineSplits[0]
					target["region"] = DefProfile
				} else {
					// Input provided: <hostname> OR <hostname>/<path>
					hostnamePath := lineSplits[0]

					if strings.Index(hostnamePath, "/") >= 0 {
						target["hostname"] = strings.Split(hostnamePath, "/")[0]
						target["path"] = strings.Join(
							strings.Split(hostnamePath, "/")[1:],
							"/")
					} else {
						target["hostname"] = hostnamePath
						target["path"] = ""
					}
					target["port"] = DefPort
				}
			} else if len(lineSplits) == 2 {
				if strings.Index(lineSplits[1], "//") >= 0 {
					// Input provided: protocol://<hostname|aws_profile>
					target["protocol"] = lineSplits[0]
					if target["protocol"] == "aws" {
						// Input provided: aws://<hostname|aws_profile>
						target["profile"] = strings.ReplaceAll(lineSplits[1], "/", "")
						target["region"] = DefProfile
					} else {
						// Input provided: protocol://<hostname>/<path>
						hostnamePath := strings.Split(lineSplits[1], "//")[1]
						if strings.Index(hostnamePath, "/") >= 0 {
							target["hostname"] = strings.Split(hostnamePath, "/")[0]
							target["path"] = strings.Join(
								strings.Split(hostnamePath, "/")[1:],
								"/")
						} else {
							target["hostname"] = hostnamePath
							target["path"] = ""
						}
						if target["protocol"] == "https" {
							target["port"] = "443"
						} else {
							target["port"] = "80"
						}
					}

				} else {
					// Input provided: <hostname|aws_profile>:<port|region>
					target["protocol"] = DefProtocol
					if target["protocol"] == "aws" {
						// Input provided: <aws_profile>:<region>
						target["profile"] = lineSplits[0]
						target["region"] = lineSplits[1]
					} else {
						// Input provided: <hostname>:<port>
						target["hostname"] = lineSplits[0]
						portPath := lineSplits[1]
						if strings.Index(portPath, "/") >= 0 {
							target["port"] = strings.Split(portPath, "/")[0]
							target["path"] = strings.Join(
								strings.Split(portPath, "/")[1:],
								"/")
						} else {
							target["port"] = portPath
							target["path"] = ""
						}
					}
				}
			} else {
				// Input provided: protocol://<hostname|aws_profile>:<port|region>/<path>
				target["protocol"] = lineSplits[0]
				if target["protocol"] == "aws" {
					target["profile"] = strings.ReplaceAll(lineSplits[1], "/", "")
					target["region"] = lineSplits[2]
				} else {
					// Protocol, hostname, port all specified
					target["hostname"] = strings.ReplaceAll(lineSplits[1], "/", "")
					portPath := lineSplits[2]
					if strings.Index(portPath, "/") >= 0 {
						target["port"] = strings.Split(portPath, "/")[0]
						target["path"] = strings.Join(
							strings.Split(portPath, "/")[1:],
							"/")
					} else {
						target["port"] = portPath
						target["path"] = ""
					}
				}
			}

			// Define a base path on which to run the scan/make request
			target["basepath"] = target["protocol"] + "://" + target["hostname"] +
				":" + target["port"]
			if target["path"] != "" {
				target["basepath"] += "/" + target["path"]

				// Remove trailing slash in basepath, so URLs created correctly
				basePath := target["basepath"]
				if basePath[len(basePath)-1] == '/' {
					target["basepath"] = basePath[:len(basePath)-1]
				}
			}

			// Limit number of hosts/targets processed
			if *limit > 0 && numTargetsRead > *limit {
				break
			}

			// Start processing each file concurrently for the given hostname
			for _, sigFile := range sigFiles {
				wg.Add(1)

				// Get the signature file content previously opened and read
				sigFileContent := sigFileContents[sigFile]

				go worker(sigFileContent, target, *verbose, &wg)
			}
		}
	}

	// Wait for all threads to end
	wg.Wait()
}
