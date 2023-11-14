package main

import "io"
import "os"
import "fmt"
import "io/fs"
import "errors"
import "os/exec"
import "path/filepath"
import "compress/gzip"
import "github.com/nlepage/go-tarfs"
import "github.com/gabriel-vasile/mimetype"
import "github.com/ajblkf/microscope/localdb"
import "github.com/ajblkf/microscope/binscan"
import "github.com/ajblkf/microscope/pkgscan"

func main () {
	database := new(localdb.Database)

	args := os.Args[1:]
	argMap := map[string] []string { }
	currentFlag := ""
	for len(args) != 0 {
		arg := args[0]
		args = args[1:]

		if len(arg) > 0 && arg[0] == '-' {
			currentFlag = arg
			argMap[currentFlag] = nil
		} else {
			argMap[currentFlag] = append(argMap[currentFlag], arg)
		}
	}

	die := func () {
		usage()
		os.Exit(2)
	}
	
	var tasks   []func ()
	var binVuln []binscan.Vulnerability
	var pkgVuln []pkgscan.Vulnerability
	var errors  []error

	appendError := func (err error) {
		if err == nil { return }
		errors = append(errors, err)
	}
	appendTask := func (task func ()) {
		tasks = append(tasks, task)
	}
	appendBinVuln := func (vulns ...binscan.Vulnerability) {
		binVuln = append(binVuln, vulns...)
	}
	appendPkgVuln := func (vulns ...pkgscan.Vulnerability) {
		pkgVuln = append(pkgVuln, vulns...)
	}

	for flag, args := range argMap {
	switch flag {
	// Specify a deny list of unwanted packages
	case "-pkgdb":
		if len(args) != 1 { die() }
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[0], err)
			os.Exit(1)
		}
		err = database.ReadPackageDb(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[0], err)
			os.Exit(1)
		}
		file.Close()

	// Specify a deny list of unwanted files
	case "-db":
		if len(args) != 1 { die() }
		file, err := os.Open(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[0], err)
			os.Exit(1)
		}
		err = database.ReadFileDb(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v: %v\n", os.Args[0], err)
			os.Exit(1)
		}
		file.Close()

	// Recursively scan a list of files or directories
	case "-files": if len(args) == 0 { die() }; appendTask(func () {
		for _, file := range args {
			list, err := binscan.Scan(os.DirFS(file), ".", database)
			appendBinVuln(list...)
			appendError(err)
		}
	})

	// Scan packages installed on the system
	case "-pkg": if len(args) != 0 { die() }; appendTask(func () {
		list, err := pkgscan.Scan(os.DirFS("/"), database)
		appendPkgVuln(list...)
		appendError(err)
	})

	// Scan dependencies of an NPM project
	case "-npm": if len(args) != 1 { die() }; appendTask(func () {
		for _, project := range args {
			list, err := scanNPMProject(os.DirFS(project), ".", database)
			appendPkgVuln(list...)
			appendError(err)
		}
	})

	// Scan files installed in a docker container
	case "-docker-files": if len(args) == 0 { die() }; appendTask(func () {
		if len(args) == 0 { return }
		temporary, err := extractDockerContainer(args[0])
		appendError(err)
		if err != nil { return }
		defer temporary.Close()
		defer os.Remove(temporary.Name())
		filesystem, err := archiveFs(temporary)
		appendError(err)
		if err != nil { return }

		for _, file := range args[1:] {
			list, err := binscan.Scan(filesystem, file, database)
			appendBinVuln(list...)
			appendError(err)
		}
	})

	// Scan packages installed in a docker container
	case "-docker-pkg": if len(args) == 0 { die() }; appendTask(func () {
		if len(args) == 0 { return }
		temporary, err := extractDockerContainer(args[0])
		appendError(err)
		if err != nil { return }
		defer temporary.Close()
		defer os.Remove(temporary.Name())
		filesystem, err := archiveFs(temporary)
		appendError(err)
		if err != nil { return }
		
		list, err := pkgscan.Scan(filesystem, database)
		appendPkgVuln(list...)
		appendError(err)
	})

	// Scan files contained in an archive
	case "-archive-files": if len(args) == 0 { die() }; appendTask(func () {
		file, err := os.Open(args[0])
		appendError(err)
		if err != nil { return }
		defer file.Close()
		filesystem, err := archiveFs(file)
		appendError(err)
		if err != nil { return }

		for _, file := range args[1:] {
			list, err := binscan.Scan(filesystem, file, database)
			appendBinVuln(list...)
			appendError(err)
		}
	})

	// Scan packages installed in an archive of a filesystem
	case "-archive-pkg": if len(args) != 1 { die() }; appendTask(func () {
		file, err := os.Open(args[0])
		appendError(err)
		if err != nil { return }
		defer file.Close()
		filesystem, err := archiveFs(file)
		appendError(err)
		if err != nil { return }

		list, err := pkgscan.Scan(filesystem, database)
		appendPkgVuln(list...)
		appendError(err)
	})

	// Scan dependencies of an NPM project inside of a docker container
	case "-docker-npm": if len(args) < 2 { die () }; appendTask(func () {
		if len(args) == 0 { return }
		temporary, err := extractDockerContainer(args[0])
		appendError(err)
		if err != nil { return }
		defer temporary.Close()
		defer os.Remove(temporary.Name())
		filesystem, err := archiveFs(temporary)
		appendError(err)
		if err != nil { return }

		for _, project := range args[1:] {
			list, err := scanNPMProject(filesystem, project, database)
			appendPkgVuln(list...)
			appendError(err)
		}
	})

	default: die()
	}}

	for _, task := range tasks {
		task()
	}

	for _, err := range errors {
		fmt.Fprintf (
			os.Stderr, "%v: %v\n",
			os.Args[0], err)
	}
	for _, vulnerability := range binVuln {
		fmt.Println(vulnerability)
	}
	for _, vulnerability := range pkgVuln {
		fmt.Println(vulnerability)
	}
	
	fmt.Fprintf (
		os.Stderr, "%v: %v errors, %v vulns\n",
		os.Args[0], len(errors), len(pkgVuln) + len(binVuln))
	if len(errors) > 0 || len(pkgVuln) > 0 || len(binVuln) > 0 {
		os.Exit(1)
	}
}

func usage () {
	fmt.Fprintf (
		os.Stderr, "Usage: %s OPTION... \n\n",
		os.Args[0])
	// TODO print options
}

func extractDockerContainer (containerName string) (*os.File, error) {
	temp, err := os.CreateTemp("", "microscope_*.tar")
	if err != nil { return nil, err }
	tempName := temp.Name()
	temp.Close()

	command := exec.Command (
			"docker", "export",
			"--output=" + tempName,
			containerName)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	fmt.Fprintf (
		os.Stderr, "%v: running %v\n",
		os.Args[0], command)
	err = command.Run()
	if err != nil {
	fmt.Fprintf (
		os.Stderr, "%v: docker extract error: %v\n",
		os.Args[0], err)
	}
	
	return os.Open(tempName)
}

func archiveFs (file io.ReadSeeker) (fs.FS, error) {
	mime, err := mimetype.DetectReader(file)
	if err != nil { return nil, err }
	file.Seek(0, io.SeekStart)

	switch {
	case mime.Is("application/gzip"):
		file, err := gzip.NewReader(file)
		if err != nil { return nil, err }
		return tarfs.New(file)
		
	case mime.Is("application/x-tar"):
		return tarfs.New(file)

	default:
		return nil, errors.New(fmt.Sprint("unknown file type ", mime))
	}
}

func scanNPMProject (filesystem fs.FS, project string, database pkgscan.Database) ([]pkgscan.Vulnerability, error) {
	packageLock, err := filesystem.Open(
		filepath.Join(project,
		"package-lock.json"))
	if err != nil { return nil, err }
	return pkgscan.ScanNPM(packageLock, database)
}
