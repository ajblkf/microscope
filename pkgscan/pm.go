package pkgscan

import "io"
import "io/fs"

// PackageReader provides sequential access to a list of installed packages.
type PackageReader interface {
	// Next returns the next package in the reader. It must return io.EOF
	// if it has reached the end of the list.
	Next () (Package, error)
}

// ScanPackageReader scans a package reader until it returns io.EOF.
func ScanPackageReader (reader PackageReader, database Database) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability
	eof := false
	for !eof {
		pack, err := reader.Next()
		eof = err == io.EOF
		if !eof && err != nil { return vulnerabilities, err }

		vulnerability, err := database.CheckPackage(pack)
		if vulnerability != nil {
			vulnerabilities = append(vulnerabilities, *vulnerability)
		}
		if err != nil { return vulnerabilities, err }
	}

	return vulnerabilities, nil
}


func ScanPacman (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	// TODO
	return nil, nil
}

func ScanXBPS (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	// TODO
	return nil, nil
}

func ScanFlatpak (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	// TODO
	return nil, nil
}

func ScanSnap (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	// TODO
	return nil, nil
}
