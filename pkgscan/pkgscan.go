package pkgscan

import "os"
import "fmt"
import "io/fs"
import "strings"
import "github.com/ajblkf/microscope/pmdetect"

type Database interface {
	CheckPackage (Package) (*Vulnerability, error)
}

type Package struct {
	Name       string
	Version    string
	Release    string
	Repository string
}

func ParsePackage (input string) Package {
	const (
		stateNamePart int = iota
		stateNameDash
		stateVersion
	); state := stateNamePart

	var pack Package

	for len(input) > 0 {
		ch := input[0]
		input = input[1:]
		
		switch state {
		case stateNamePart:
			if ch == '-' {
				state = stateNameDash
			} else {
				pack.Name += string(ch)
			}

		case stateNameDash:
			if ch >= '0' && ch <= '9' {
				state = stateVersion
				pack.Version += string(ch)
			} else {
				state = stateNamePart
				pack.Name += "-"
				pack.Name += string(ch)
			}

		case stateVersion:
			pack.Version += string(ch)
		}
	}

	pack.Version, pack.Release,    _ = strings.Cut(pack.Version, "-")
	pack.Release, pack.Repository, _ = strings.Cut(pack.Release, ":")

	return pack
}

func (this Package) String () string {
	return fmt.Sprintf("%v-%v-%v:%v", this.Name, this.Version, this.Release, this.Repository)
}

type Vulnerability struct {
	// The vulnerable package
	Package Package
	// Where the vulnerability was mentioned
	Source string
	// Description of the vulnerability
	Reason string
}

func (this Vulnerability) String () string {
	return fmt.Sprintf("%v\t%s\t%s", this.Package, this.Source, this.Reason)
}

func Scan (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	pms := pmdetect.Detect(filesystem)
	if len(pms) == 0 {
		fmt.Fprintf (
			os.Stderr, "%v: no package managers detected\n",
			os.Args[0])
	}
	for _, pm := range pms {
		vulnPiece, err := ScanPackageManager(filesystem, database, pm)
		vulnerabilities = append(vulnerabilities, vulnPiece...)
		if err != nil { return vulnerabilities, err }
	}

	return vulnerabilities, nil
}

// ScanPackageManager scans for vulnerabilities in packages installed by the
// specified package manager.
func ScanPackageManager (
	filesystem fs.FS,
	database Database,
	pm pmdetect.PackageManager,
) (
	[]Vulnerability,
	error,
) {
	fmt.Fprintf (
		os.Stderr, "%v: scanning %v\n",
		os.Args[0], pm)
	switch pm {
	case pmdetect.PmAPT:     return ScanAPT(filesystem, database)
	case pmdetect.PmAPK:     return ScanAPK(filesystem, database)
	case pmdetect.PmDNF:     return ScanDNF(filesystem, database)
	case pmdetect.PmPacman:  return ScanPacman(filesystem, database)
	case pmdetect.PmXBPS:    return ScanXBPS(filesystem, database)
	case pmdetect.PmFlatpak: return ScanFlatpak(filesystem, database)
	case pmdetect.PmSnap:    return ScanSnap(filesystem, database)
	default: return nil, nil
	}
}
