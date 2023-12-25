// oki automates the execution of pledge(2) and unveil(2)
package main

// (cd ~/src/oki && GOOS=openbsd go build && scp oki re-shared-obsd:~/)
import (
	"bytes"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	appName = "oki"
	usage   = appName + `

SYNOPSIS
  ` + appName + ` [options] </path/to/program|program-in-path>

DESCRIPTION
  ` + appName + ` automates execution of pledge(2) and unveil(2) to reduce the blast
  radius of a program. Blast radius refers to the overall impact of a potential
  security compromise.

  The promise string provided to the -` + promisesArg + ` flag is passed to the pledge(2)
  system call and should match one of the promises listed in pledge(2) manual.

  The string provided to the -` + unveilsArg + ` flag should be formatted as "permission:path"
  (e.g. "r:/tmp"). The permission string should match one or more of the
  permission characters in the unveil(2) manual.

  By default ` + appName + ` will pass the HOME and PATH environment variables to the
  child process. This behavior can be changed with the -` + passAllEnvironArg + ` flag to pass all
  environment variables to the child process.

EXAMPLES
  For examples, please execute: ` + appName + ` -` + advHelpArg + `

SEE ALSO
  pledge(2), unveil(2)

OPTIONS
`
	advHelpDoc = appName + `

EXAMPLES
  o  The following example autogenerates unveil rules for the rizin program:

       $ ` + appName + ` -` + autogenerateUnveilRulesArg + ` /usr/local/bin/rizin` + `

  o  The following example runs ` + appName + ` on the git program:

       $ ` + appName + ` -` + promisesArg + ` "stdio" -` + promisesArg + ` "inet" -` + promisesArg +
		` "error" -` + unveilsArg + ` "r:/tmp" -` + unveilsArg + ` "rc:/foo" -- git pull

     The above example enforces the pledge(2) promises: "stdio", "inet",
     and "error". It also runs unveil(2) on the following paths:
       - "/tmp" for read (r) operations
       - "/foo" for read (r) and create/remove (c) operations
`

	outputPrefixEnv = "OKI_OUTPUT_PREFIX"

	passAllEnvironArg          = "E"
	advHelpArg                 = "H"
	autogenerateUnveilRulesArg = "R"
	debugArg                   = "d"
	passEnvironArg             = "e"
	helpArg                    = "h"
	allowNoPromisesArg         = "k"
	promisesArg                = "p"
	unveilsArg                 = "u"
	skipExeUnveilArg           = "x"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

// oki -p "stdio" -p "inet" -p "error" -u "r:/tmp" -u "rc:/foo" -- rizin -AA /tmp/memla
// oki -U "r:/usr/local/lib/librz_.*" -- rizin -AA /tmp/memla
// oki -U "r:/usr/local/lib/librz_*" -- rizin -AA /tmp/memla
func mainWithError() error {
	passAllEnviron := flag.Bool(
		passAllEnvironArg,
		false,
		"Pass all environment variables to the child process. If not\n"+
			"specified only HOME and PATH are passed")

	advHelp := flag.Bool(
		advHelpArg,
		false,
		"Display advanced usage information and examples")

	getELFDepUnveilPaths := flag.Bool(
		autogenerateUnveilRulesArg,
		false,
		"Generate the unveil(2) rules for exe dependencies and exit.\n"+
			"This assumes exe is an ELF file (specify rule prefix by setting the\n"+
			outputPrefixEnv+" environment variable)")

	debug := flag.Bool(
		debugArg,
		false,
		"Enable debug logging")

	var environs environFlag
	flag.Var(
		&environs,
		passEnvironArg,
		"Pass environment `variable` to the child process (can be specified\n"+
			"multiple times)")

	help := flag.Bool(
		helpArg,
		false,
		"Display this information")

	allowNoPromises := flag.Bool(
		allowNoPromisesArg,
		false,
		"Allow no pledge(2) promises to be specified")

	// change the default argument name from "value"
	// https://stackoverflow.com/questions/71807493/go-flag-usage-description-contains-the-word-value
	var promises promiseFlag
	flag.Var(
		&promises,
		promisesArg,
		"The pledge(2) `promise` string (can be specified multiple times)")

	var unveils unveilFlag
	flag.Var(
		&unveils,
		unveilsArg,
		"The unveil(2) colon separated `permission:path` (can be\n"+
			"specified multiple times)")

	skipExeUnveil := flag.Bool(
		skipExeUnveilArg,
		false,
		"Skip unveil(2) of the exe path")

	// This prevents the flag library from running flag.PrintDefaults
	// when a flag parse error occurs
	// This makes error messages much more readable for the user :)
	flag.Usage = func() {}

	flag.Parse()

	if *help {
		_, _ = os.Stderr.WriteString(usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *advHelp {
		_, _ = os.Stderr.WriteString(advHelpDoc)
		os.Exit(1)
	}

	if flag.NArg() == 0 {
		return fmt.Errorf("please specify a program to execute")
	}

	exeName := flag.Arg(0)
	exePath, err := exec.LookPath(exeName)
	if err != nil {
		return fmt.Errorf("failed to find %q PATH - %w", exeName, err)
	}

	// TODO apply unveil to getELFDepUnveilPaths
	// Default to unveiling /usr/lib and /usr/local/lib and make customizable with environment variable.
	// Check if run path contains a non permitted directory and return error message with directory to user.
	if *getELFDepUnveilPaths {
		err := unix.Pledge("stdio rpath", "")
		if err != nil {
			return fmt.Errorf("failed to pledge - %w", err)
		}

		foundLibPaths := make(map[string]struct{})
		libBuf := bytes.NewBuffer(nil)

		err = elfDepUnveilPaths(exePath, foundLibPaths, libBuf)
		if err != nil {
			return fmt.Errorf("failed to get ELF dependencies unveil paths - %w", err)
		}

		_, err = os.Stdout.Write(libBuf.Bytes())
		if err != nil {
			return fmt.Errorf("failed to write unveil rules to stdout - %w", err)
		}

		return nil
	}

	promisesStr := strings.TrimSpace(strings.Join(promises.promises, " "))

	if promisesStr == "" && !*allowNoPromises {
		return fmt.Errorf("please specify a promise with '-%s' or use '-%s' to allow no promises",
			promisesArg, allowNoPromisesArg)
	}

	// var debugLogger *log.Logger
	debugLogger := log.New(io.Discard, "", 0)
	if *debug {
		debugLogger = log.New(log.Writer(), "[debug] ", log.Flags()|log.Lmsgprefix)
	}

	if promisesStr != "" {
		debugLogger.Printf("executing promise string: %q...", promisesStr)

		err := unix.PledgeExecpromises(promisesStr)
		if err != nil {
			return fmt.Errorf("failed pledge exec - %w", err)
		}
	}

	if !*skipExeUnveil {
		exePerms := "rx"
		debugLogger.Printf("automatically unveiling \"%s:%s\"...", exePerms, exePath)

		err = unix.Unveil(exePath, exePerms)
		if err != nil {
			return fmt.Errorf("failed to automatically unveil %q - %w", exePath, err)
		}
	}

	for _, unveil := range unveils.unveils {
		debugLogger.Printf("unveiling %q...", unveil.String())

		err := unix.Unveil(unveil.filePath, unveil.perms)
		if err != nil {
			return fmt.Errorf("failed to unveil %q - %w", unveil.String(), err)
		}
	}

	err = unix.UnveilBlock()
	if err != nil {
		return fmt.Errorf("failed to unveil block - %w", err)
	}

	// TODO if both -E -e then return an error
	// example "-e SSH_AUTH_SOCK -e AWS_IAM_SECRET"
	var environment []string
	for _, environ := range environs.environs {
		val, present := os.LookupEnv(environ)
		if present {
			environment = append(environment, environ+"="+val)
		} else {
			return fmt.Errorf("%q environment variable not found", environ)
		}
	}

	if *passAllEnviron {
		environment = os.Environ()
	} else {
		environment = append(environment, "HOME="+os.Getenv("HOME"), "PATH="+os.Getenv("PATH"))
	}

	if debugLogger.Writer() != io.Discard {
		for _, keyValue := range environment {
			name, _, _ := strings.Cut(keyValue, "=")
			debugLogger.Printf("passing environment variable: %q...", name)
		}
	}

	err = syscall.Exec(exePath, append([]string{exePath}, flag.Args()[1:]...), environment)
	if err != nil {
		return fmt.Errorf("failed to exec %q - %w", exePath, err)
	}

	return nil
}

func elfDepUnveilPaths(elfPath string, foundLibPaths map[string]struct{}, libBuf io.Writer) error {
	f, err := elf.Open(elfPath)
	if err != nil {
		return fmt.Errorf("failed to open ELF %q - %w", elfPath, err)
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		return fmt.Errorf("failed to find imported libraries - %w", err)
	}

	if len(libs) == 0 {
		return nil
	}

	runPaths, err := f.DynString(elf.DT_RUNPATH)
	if err != nil {
		return fmt.Errorf("failed to find DT_RUNPATH tag - %w", err)
	}

	// TODO should we trust the elf to tell us which directories to load libraries from
	runPaths = append(runPaths, "/usr/lib")

	for _, lib := range libs {
		if strings.Contains(lib, "../") {
			return fmt.Errorf("imported library contains ../ - %q", lib)
		}

		if strings.Contains(lib, "/") {
			return fmt.Errorf("imported library contains / - %q", lib)
		}

		foundLib := false

		for _, runPath := range runPaths {
			libPath := filepath.Join(runPath, lib)

			fileInfo, err := os.Stat(libPath)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					continue
				}

				return fmt.Errorf("failed to stat library path: %q - %w", libPath, err)
			}

			if fileInfo.IsDir() {
				return fmt.Errorf("library path is a directory: %q", libPath)
			}

			// TODO add check for shell characters
			_, hasLib := foundLibPaths[libPath]
			if !hasLib {
				libBuf.Write([]byte(os.Getenv(outputPrefixEnv) + "-" + unveilsArg +
					" 'r:" + libPath + "' \\\n"))

				foundLibPaths[libPath] = struct{}{}

				err = elfDepUnveilPaths(libPath, foundLibPaths, libBuf)
				if err != nil {
					return err
				}
			}

			foundLib = true
			break
		}

		// TODO add flag to make this error a log message
		if !foundLib {
			return fmt.Errorf("could not find library: %q - searched in %q", lib, runPaths)
		}

	}

	return nil
}

type environFlag struct {
	environs []string
}

func (o *environFlag) String() string {
	if len(o.environs) == 0 {
		return ""
	}

	return "'" + strings.Join(o.environs, "', '") + "'"
}

func (o *environFlag) Set(s string) error {
	o.environs = append(o.environs, s)
	return nil
}

type promiseFlag struct {
	promises []string
}

func (o *promiseFlag) String() string {
	if len(o.promises) == 0 {
		return ""
	}

	return "'" + strings.Join(o.promises, "', '") + "'"
}

func (o *promiseFlag) Set(s string) error {
	o.promises = append(o.promises, s)
	return nil
}

type unveilFlag struct {
	unveils []unveilConfig
}

func (o *unveilFlag) String() string {
	numUnveils := len(o.unveils)
	if numUnveils == 0 {
		return ""
	}

	str := "'"
	for i, config := range o.unveils {
		str += config.String() + "'"
		if numUnveils > 1 && i != numUnveils-1 {
			str += ", '"
		}
	}
	return str
}

func (o *unveilFlag) Set(s string) error {
	perms, filePath, sepPresent := strings.Cut(s, ":")
	if !sepPresent {
		return fmt.Errorf("please separate unveil permissions and filepath with a ':'")
	}

	if strings.TrimSpace(perms) == "" {
		return fmt.Errorf("please provide a permissions string")
	}

	if strings.TrimSpace(filePath) == "" {
		return fmt.Errorf("please provide a filepath")
	}

	o.unveils = append(o.unveils, unveilConfig{
		perms:    perms,
		filePath: filePath,
	})

	return nil
}

type unveilConfig struct {
	perms    string
	filePath string
}

func (o *unveilConfig) String() string {
	return fmt.Sprintf("%s:%s", o.perms, o.filePath)
}
