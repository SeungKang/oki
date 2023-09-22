// (cd ~/src/oki && GOOS=openbsd go build && scp oki re-shared-obsd:~/)
package main

import (
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

// TODO make debug showing what pledges and unveils are used
// oki -p "stdio" -p "inet" -p "error" -u "r:/tmp" -u "rc:/foo" -- rizin -AA /tmp/memla
// oki -U "r:/usr/local/lib/librz_.*" -- rizin -AA /tmp/memla
// oki -U "r:/usr/local/lib/librz_*" -- rizin -AA /tmp/memla
func mainWithError() error {
	var promises promiseFlag
	flag.Var(
		&promises,
		"p",
		"the pledge(2) promise string (can be specified multiple times)")

	var unveils unveilFlag
	flag.Var(
		&unveils,
		"u",
		"the unveil(2) colon separated permission:filepath (can be specified multiple times)")

	allowNoPromises := flag.Bool(
		"k",
		false,
		"allow no pledge(2) promises to be specified")

	skipExeUnveil := flag.Bool(
		"x",
		false,
		"skip unveil(2) of the exe path")

	getELFDepUnveilPaths := flag.Bool(
		"R",
		false,
		"generate the unveil(2) rules for exe dependencies and exit\n"+
			"(assumes exe is an ELF file)")

	flag.Parse()

	if flag.NArg() == 0 {
		return fmt.Errorf("please specify a program to execute")
	}

	exeName := flag.Arg(0)
	// TODO consider not using this as default behavior
	exePath, err := exec.LookPath(exeName)
	if err != nil {
		return fmt.Errorf("failed to find %q PATH - %w", exeName, err)
	}

	// TODO apply pledge and unveil to getELFDepUnveilPaths
	if *getELFDepUnveilPaths {
		foundLibPaths := make(map[string]struct{})
		err := elfDepUnveilPaths(exePath, foundLibPaths)
		if err != nil {
			return fmt.Errorf("failed to get ELF dependencies unveil paths - %w", err)
		}

		return nil
	}

	if !*skipExeUnveil {
		err = unix.Unveil(exePath, "rx")
		if err != nil {
			return fmt.Errorf("failed to automatically unveil %q - %w", exePath, err)
		}
	}

	for _, unveil := range unveils.unveils {
		err := unix.Unveil(unveil.filePath, unveil.perms)
		if err != nil {
			return fmt.Errorf("failed to unveil %q - %w", unveil.String(), err)
		}
	}

	err = unix.UnveilBlock()
	if err != nil {
		return fmt.Errorf("failed to unveil block - %w", err)
	}

	promisesStr := strings.TrimSpace(strings.Join(promises.promises, " "))

	// TODO make -k a constant
	if promisesStr == "" && !*allowNoPromises {
		return errors.New("please specify a promise with '-p' or use '-k' to allow no promises")
	}

	if promisesStr != "" {
		err = unix.PledgeExecpromises(promisesStr)
		if err != nil {
			return fmt.Errorf("failed pledge exec - %w", err)
		}
	}

	// TODO filter environment variables
	err = syscall.Exec(exePath, append([]string{exePath}, flag.Args()[1:]...), os.Environ())
	if err != nil {
		return fmt.Errorf("failed to exec %q - %w", exePath, err)
	}

	return nil
}

func elfDepUnveilPaths(elfPath string, foundLibPaths map[string]struct{}) error {
	f, err := elf.Open(elfPath)
	if err != nil {
		return fmt.Errorf("failed to open ELF %q - %w", elfPath, err)
	}
	defer f.Close()

	// TODO check if no imported libraries returns an error
	libs, err := f.ImportedLibraries()
	if err != nil {
		return fmt.Errorf("failed to find imported libraries - %w", err)
	}

	// TODO do not error if there are no DT_RUNPATH tags
	// TODO check if dynstring returns error when there are no instances of DT_RUNPATH
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

			_, hasLib := foundLibPaths[libPath]
			if !hasLib {
				log.Printf("lib path: %q - from: %q", libPath, elfPath)
				foundLibPaths[libPath] = struct{}{}

				err = elfDepUnveilPaths(libPath, foundLibPaths)
				if err != nil {
					return err
				}
			}

			foundLib = true
			break
		}

		if !foundLib {
			log.Printf("could not find the library path for: %q", lib)
			continue
		}

	}

	return nil
}

type promiseFlag struct {
	promises []string
}

func (o *promiseFlag) String() string {
	// TODO fix formatting
	return strings.Join(o.promises, " ")
}

func (o *promiseFlag) Set(s string) error {
	o.promises = append(o.promises, s)
	return nil
}

type unveilFlag struct {
	unveils []unveilConfig
}

func (o *unveilFlag) String() string {
	var str string
	// TODO fix formatting
	for _, config := range o.unveils {
		str += config.String() + " "
	}
	return str
}

func (o *unveilFlag) Set(s string) error {
	perms, filePath, sepPresent := strings.Cut(s, ":")
	if !sepPresent {
		return fmt.Errorf("please separate unveil permissions and filepath with a ':'")
	}

	// TODO check if error message has enough information
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
