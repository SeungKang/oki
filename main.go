// (cd ~/src/oki && GOOS=openbsd go build && scp oki re-shared-obsd:~/)
package main

import (
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln("fatal:", err)
	}
}

// oki -p "stdio" -p "inet" -p "error" -u "r:/tmp" -u "rc:/foo" -- rizin -AA /tmp/memla
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

	flag.Parse()

	if flag.NArg() == 0 {
		return fmt.Errorf("please specify a program to execute")
	}

	exeName := flag.Arg(0)
	exePath, err := exec.LookPath(exeName)
	if err != nil {
		return fmt.Errorf("failed to find %q PATH - %w", exeName, err)
	}

	err = unix.Unveil(exePath, "rx")
	if err != nil {
		return fmt.Errorf("failed to unveil %q - %w", exePath, err)
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
