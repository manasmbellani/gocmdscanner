package main

//Script used to scan the specified input YAML file for
//signature and run the scan
import (
	"bufio"
	"crypto/tls"
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
	"runtime"
	"strings"
	"sync"

	"gopkg.in/yaml.v2"
)

// NumOutChars - Number of output characters to print
const NumOutChars = 1000

// Delim - Delimiter to use when parsing output via regex itself
const Delim = "|"

// DefProtocol - default protocol to use if not specified
const DefProtocol = "http"

// DefPort - Default port to use if not specified
const DefPort = "80"

// HTTPSPort - HTTPS-like port
const HTTPSPort = "443"

// DefRegion - Default AWS region
const DefRegion = "ap-southeast-2"

// DefProfile - Default AWS profile
const DefProfile = "default"

// DefHTTPMethod - Default HTTP Method
const DefHTTPMethod = "GET"

// DefUserAgent - Default user agent string
const DefUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"

// DefCheckTags - Default set of Tags to assign to a check
var DefCheckTags = []string{"auto"}

// Task to perform (comprised of target with signature file name that describes
// task to perform)
type task struct {
	sigFile string
	target  map[string]string
}

// Format for an Example YAML signature files
type signFileStruct struct {
	ID   string `yaml:"id"`
	Info struct {
		Name string `yaml:"name"`
	} `yaml:"info"`
	Notes    string     `yaml:"notes"`
	Outfile  string     `yaml:"outfile"`
	Author   string     `yaml:"author"`
	Severity string     `yaml:"severity"`
	Checks   []sigCheck `yaml:"checks"`
}

// Define a separate struct for checks
type sigCheck struct {
	Cmethod    string   `yaml:"cmethod"`
	Tags       []string `yaml:"tag"`
	Cmd        []string `yaml:"cmd"`
	CmdDir     string   `yaml:"cmddir"`
	CmdTimeout int      `yaml:"cmdtimeout"`
	JoinCmds   bool     `yaml:"joincmds"`
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
	Notes    string `yaml:"notes"`
	Outfile  string `yaml:"outfile"`
	Matchers []struct {
		Type    string `yaml:"type"`
		Regex   string `yaml:"regex"`
		NoRegex string `yaml:"noregex"`
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

// convertPathToAbs - convert the path to Absolute, if needed
func convertPathToAbs(outfile string, target map[string]string) string {
	owd := target["owd"]
	if !filepath.IsAbs(outfile) {
		outfile = filepath.Join(owd, outfile)
	}
	return outfile
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
		fmt.Printf("[-] Unmarshal YAML Parsing Error: %+v in file: %s\n", err,
			sigFile)
		log.Fatalf("[-] Unmarshal YAML Parsing Error: %+v in file: %s\n", err,
			sigFile)
	}

	return sigFileContent
}

// Execute a command to get the output, error. Command is executed when in the
// optionally specified 'cmdDir' OR it is executed with the current working dir
func execCmd(cmdToExec string, cmdDir string, cmdtimeout int) string {

	// Get the original working directory
	owd, _ := os.Getwd()

	// Switch to the directory
	if cmdDir != "" {
		err := os.Chdir(cmdDir)
		if err != nil {
			log.Printf("[-] Could not switch to dir: %s. Does it exist?", cmdDir)
		}
	}

	// Get my current working directory
	cwd, _ := os.Getwd()

	log.Printf("[v] Executing cmd: %s in dir: %s\n", cmdToExec, cwd)

	// Determine how to execute the command based on OS
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd.exe", "/c", cmdToExec)
	default:
		if cmdtimeout == -1 {
			cmd = exec.Command("/bin/sh", "-c", cmdToExec)
		} else {
			timeoutstr := fmt.Sprintf("%d", cmdtimeout)
			cmd = exec.Command("timeout", timeoutstr, "/bin/sh", "-c", cmdToExec)

		}
	}

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

	// Print only specific number of characters
	partialTotalOut := ""
	if len(totalOut) > NumOutChars {
		partialTotalOut = totalOut[:NumOutChars] + " ..."
	} else {
		partialTotalOut = totalOut
	}

	log.Printf("Partial Output of cmd '%s':\n%s \n", cmdToExec, partialTotalOut)

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
			pathToPrint = "[" + sigID + "] " + fullURLPath
		} else {
			//pathToPrint = "[" + sigID + "] " + target["protocol"] + "://" + target["hostname"] + ":" +
			//	target["port"]
			pathToPrint = "[" + sigID + "] " + target["input"]
		}
	}

	return pathToPrint
}

// Get given match config and search output for keywords. If found, then
func runMatch(checkConfig sigCheck, outputToSearch string) bool {
	matcherFound := false
	noRegexMatcherFound := false

	// Determine what type of matcher was provided
	matchers := checkConfig.Matchers
	for _, matcher := range matchers {
		matcherType := matcher.Type
		if matcherType == "" || strings.ToLower(matcherType) == "regex" {
			strToSearch := strings.ReplaceAll(outputToSearch, "\n", Delim)
			strToSearch = strings.ReplaceAll(strToSearch, "\r", Delim)

			// First check if there is regex that should not be present
			noRegex := matcher.NoRegex
			if noRegex != "" {
				found, err := regexp.MatchString(noRegex, strToSearch)
				if err != nil {
					fmt.Printf("[-] Regex Error when running NoRegex search: %s\n", err.Error())
					log.Fatalf("[-] Regex Error when running NoRegex search: %s\n", err.Error())
				}
				if found {
					matcherFound = false
					noRegexMatcherFound = true
				}
			}

			// Then search for positive regex
			regex := matcher.Regex
			if !noRegexMatcherFound {
				found, err := regexp.MatchString(regex, strToSearch)
				if err != nil {
					fmt.Printf("[-] Regex Error when running Regex search: %s\n", err.Error())
					log.Fatalf("[-] Regex Error when running Regex search: %s\n", err.Error())
				}
				if found {
					matcherFound = true
					break
				}
			}
		} else {
			log.Fatalf("[-] Unknown matcher type: %s\n", matcherType)
		}
	}
	return matcherFound
}

// Get file name without extension only
func fileNameWOExt(filePath string) string {
	fileName := filepath.Base(filePath)
	return strings.TrimSuffix(fileName, filepath.Ext(fileName))
}

// contains - Does string array (arr) contain string (item)
func contains(arr []string, item string) bool {

	for _, i := range arr {
		if i == item {
			return true
		}
	}
	return false
}

// execCheckBasedOnTag - Execute check based on tag
func execCheckBasedOnTags(checkTags []string, tagsToExec string) bool {
	tagsToExecArr := strings.Split(tagsToExec, ",")

	// If tags to execute is set to 'all', then just execute the check
	if tagsToExec == "all" {
		return true
	}

	allTagsFound := true
	for _, tag := range tagsToExecArr {
		if !contains(checkTags, tag) {
			allTagsFound = false
			break
		}
	}
	return allTagsFound
}

// Worker function parses each YAML signature file, runs relevant commands as
// present in  each file and performs the matching operation
func worker(sigFileContents map[string]signFileStruct, tasks chan task,
	showTargetsProcessed bool, methodToExec string, tagsToExec string, wg *sync.WaitGroup) {

	// Need to let the waitgroup know that the function is done at the end...
	defer wg.Done()

	// Get each task comprising of target, signature target read from user
	for taskDef := range tasks {
		sigFile := taskDef.sigFile
		target := taskDef.target

		log.Printf("[*] Testing sigfile: %s on target: %+v\n", sigFile, target)
		if showTargetsProcessed {
			fmt.Fprintf(os.Stderr, "[*] Testing sigfile: %s on target: %+v\n",
				sigFile, target)
		}

		// Get the signature file content previously opened and read
		sigFileContent := sigFileContents[sigFile]

		// ID of the signature
		sigID := sigFileContent.ID
		if sigID == "" {
			// Extract signature from path of the signature file itself
			sigID = fileNameWOExt(sigFile)
		}

		// Are there any general notes to print from the signature file
		sigFilesNotesToPrint := ""
		sigFilesNotesToPrint = subTargetParams(sigFileContent.Notes, target)
		if sigFilesNotesToPrint != "" {
			log.Printf(sigFilesNotesToPrint)
		}

		// Build the output file
		outfile := subTargetParams(sigFileContent.Outfile, target)

		// Convert path to absolute file path
		outfile = convertPathToAbs(outfile, target)

		// Write the notes to output file
		if outfile != "" {
			contentToWrite := sigFilesNotesToPrint
			ioutil.WriteFile(outfile, []byte(contentToWrite), 0644)
		}

		// First get the list of all checks to perform from file
		myChecks := sigFileContent.Checks

		for _, myCheck := range myChecks {

			// Get the tags to execute checks, and also add the default tags
			checkTags := myCheck.Tags
			if len(checkTags) <= 0 {
				checkTags = DefCheckTags
			}

			// Add 'auto' tag to the check - by default assumed automatic
			if !contains(checkTags, "manual") &&
				!contains(checkTags, "auto") {
				checkTags = append(checkTags, "auto")
			}

			// Determine if we should execute the method on cmethod
			if execCheckBasedOnTags(checkTags, tagsToExec) {

				// Get the commmand directory to execute this command in
				cmdDir := myCheck.CmdDir

				// Get commands to execute from signature file
				cmdsToExec := myCheck.Cmd

				// Get the timeout for execution of command
				cmdtimeout := myCheck.CmdTimeout

				// Join commands to execute
				joinCmds := myCheck.JoinCmds

				cmdsOutput := ""
				requestOutput := ""

				if joinCmds {
					// Commands should be joined together and executed
					joinedCmd := strings.Join(cmdsToExec, "; ")

					// Execute commands
					cmdsToExecSub := subTargetParams(joinedCmd, target)
					cmdsOutput = cmdsOutput + "\n" + execCmd(cmdsToExecSub, cmdDir, cmdtimeout)

					// Check for a match from response
					matcherFound := runMatch(myCheck, cmdsOutput)
					if matcherFound {
						fmt.Println(formatDetection(sigID, target))
					}
				} else {

					// Run all the commands and collect output
					for _, cmdToExec := range cmdsToExec {

						// Run the commands, if not empty
						if cmdToExec != "" {
							cmdsToExecSub := subTargetParams(cmdToExec, target)
							cmdsOutput = cmdsOutput + "\n" + execCmd(cmdsToExecSub, cmdDir, cmdtimeout)
						}

						// Check for a match from response
						matcherFound := runMatch(myCheck, cmdsOutput)
						if matcherFound {
							fmt.Println(formatDetection(sigID, target))
						}
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
					req.Header.Set("X-Forwarded-For", "127.0.0.1")
					req.Header.Set("X-Forwarded-Host", "127.0.0.1")

					// Set custom headers if any are provided
					if myCheck.Headers != nil {
						for _, header := range myCheck.Headers {
							name := header.Name
							value := header.Value
							req.Header.Set(name, value)
						}
					}

					// Verbose message to be printed to let the user know
					log.Printf("Make %s request to URL: %s\n", httpMethod,
						urlToCheckSub)

					log.Println("Request Body: " + strBody)
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
							s = fmt.Sprintf("%s:%s", k, strings.Join(v, ","))
							respHeadersStr += s + ";"
						}

						// Combine status code, response headers and body
						requestOutput = string(statusCode) + "\n" + respHeadersStr + "\n" +
							string(respBody)

						// Check for a match from the response
						matcherFound := runMatch(myCheck, requestOutput)
						if matcherFound {
							fmt.Println(formatDetection(sigID, target))
						}
					}
				}

				// Are there any special notes? Write them to the output
				checkNotesToPrint := subTargetParams(myCheck.Notes, target)

				// If verbose mode is set, then print commands output and the
				// requests output - useful for debugging
				if cmdsOutput != "" {
					log.Printf(cmdsOutput)
				}

				if requestOutput != "" {
					log.Printf(requestOutput)
				}

				if checkNotesToPrint != "" {
					log.Printf("[!] " + checkNotesToPrint)
				}

				// Check if we need to store output to output file
				outfile := myCheck.Outfile
				if outfile != "" {

					// Get the command, web request, notes output together
					// to write to file
					contentToWrite := cmdsOutput + "\n" + requestOutput
					if sigFilesNotesToPrint != "" {
						contentToWrite += "\n[!] " + sigFilesNotesToPrint
					}

					if checkNotesToPrint != "" {
						contentToWrite += "\n[!] " + checkNotesToPrint
					}

					// Substitute params in the output file
					outfile = subTargetParams(outfile, target)

					// Convert path to absolute file path
					outfile = convertPathToAbs(outfile, target)

					// Writ the output to file
					ioutil.WriteFile(outfile, []byte(contentToWrite), 0644)

					// Let user know that we wrote results to an output file
					log.Printf("[*] Wrote results to outfile: %s\n", outfile)
				}
			}
		}
	}
	//log.Printf("Completed check on path: %s\n", target["basepath"])
}

func main() {
	pathsWithSigFiles := flag.String("paths", "",
		"Files/folders/file-glob patterns, containing YAML signature files")
	verbosePtr := flag.Bool("v", false, "Show commands as executed+output")
	limitPtr := flag.Uint("limit", 0, "Limit number of host:port targets processed")
	maxThreadsPtr := flag.Int("mt", 20, "Max number of goroutines to launch")
	showTargetsProcessedPtr := flag.Bool("st", false,
		"Show targets processed to track progress, as goroutines process targets")
	methodToExecPtr := flag.String("cm", "all", "Methods of signature file to exec")
	tagsToExecPtr := flag.String("t", "all", "Tags that should be present in checks. "+
		"If multiple, then 'all' tags must be present")
	flag.Parse()

	maxThreads := *maxThreadsPtr
	limit := *limitPtr
	showTargetsProcessed := *showTargetsProcessedPtr
	methodToExec := *methodToExecPtr
	tagsToExec := *tagsToExecPtr

	// Check if logging should be enabled
	verbose := *verbosePtr
	if !verbose {
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}

	if *pathsWithSigFiles == "" {
		fmt.Println("[-] Signature files must be provided.")
	}

	log.Println("Convert the comma-sep list of files, folders to loop through")
	pathsToCheck := strings.Split(*pathsWithSigFiles, ",")

	// List of all files in the folders/files above
	var filesToParse []string

	log.Println("Loop through each path to to discover all files")
	for _, pathToCheck := range pathsToCheck {
		// Check if glob file-pattern provided
		log.Printf("Reviewing path: %s\n", pathToCheck)
		if strings.Index(pathToCheck, "*") >= 0 {
			matchingPaths, _ := filepath.Glob(pathToCheck)
			for _, matchingPath := range matchingPaths {
				filesToParse = append(filesToParse, matchingPath)
			}

		} else {

			//Check if file path exists
			fi, err := os.Stat(pathToCheck)
			if err != nil {
				log.Fatalf("[-] Path: %s not found\n", pathToCheck)
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

	log.Printf("Total number of files: %d\n", len(filesToParse))

	// Get all the Yaml files filtered based on the extension
	sigFiles := findSigFiles(filesToParse)

	log.Printf("Number of signature  files: %d\n", len(sigFiles))

	// parse information from each signature file and store it so it doesn't
	// have to be read again & again
	sigFileContents := make(map[string]signFileStruct, len(sigFiles))
	for _, sigFile := range sigFiles {
		log.Printf("Parsing signature file: %s\n", sigFile)
		sigFileContents[sigFile] = parseSigFile(sigFile)
	}

	// List of the targets URL/hostname to process
	tasks := make(chan task)

	// Starting max number of concurrency threads
	var wg sync.WaitGroup
	for i := 1; i <= maxThreads; i++ {
		wg.Add(1)

		log.Printf("Launching goroutine: %d for assessing targets\n", i)
		go worker(sigFileContents, tasks, showTargetsProcessed,
			methodToExec, tagsToExec, &wg)
	}

	log.Println("Disabling SSL Certificate checks for http client")
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

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

			// Add original input line also into the target
			target["input"] = line

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

						// Intelligently, select HTTPS port (443) for HTTPS protocol
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

						// Intelligently guess protocol if 'HTTPSPort' present in port definition e.g. 443, 8443, 9443, etc. Otherwise,
						// default to HTTP
						if strings.Contains(target["port"], HTTPSPort) {
							target["protocol"] = "https"
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

			// Add the current working directory
			target["owd"], _ = os.Getwd()

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

			// Define some additional aliases useful for sub'bing in YAML file
			target["host"] = target["hostname"]
			target["domain"] = target["hostname"]

			log.Printf("Adding each sigfile with target as task for processing: %+v\n", target)
			for _, sigFile := range sigFiles {
				var taskDef task
				taskDef.target = target
				taskDef.sigFile = sigFile
				tasks <- taskDef
			}

			// Limit number of hosts/targets processed
			if limit > 0 && numTargetsRead > limit {
				log.Printf("Stopped adding new targets. Limit: %d hits\n", limit)
				break
			}
		}
	}

	// Read all targets from user, nothing further to add
	close(tasks)

	// Wait for all threads to finish processing
	wg.Wait()
}
