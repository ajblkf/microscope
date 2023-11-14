package binscan

import "fmt"
import "io/fs"

type Database interface {
	CheckFile (filesystem fs.FS, path string) (*Vulnerability, error)
}

type Vulnerability struct {
	// The path to the file (in given filesystem)
	Name   string
	// The hash of the file
	Hash   string
	// Where the vulnerability was mentioned
	Source string
	// Description of the vulnerability
	Reason string
}

func (this Vulnerability) String () string {
	return fmt.Sprintf("%s\t%s\t%s\t%s", this.Name, this.Hash, this.Source, this.Reason)
}

func Scan (filesystem fs.FS, root string, database Database) ([]Vulnerability, error) {
	var vulnerabilities []Vulnerability

	// for every file in given filesystem
	walker := func (path string, entry fs.DirEntry, err error) error {
		if err != nil    { return err }
		if entry.IsDir() { return nil }
		vulnerability, err := database.CheckFile(filesystem, path)
		if err != nil    { return err }
		if vulnerability != nil {
			vulnerabilities = append (
				vulnerabilities,
				*vulnerability)
		}
		return nil
	}
	
	err := fs.WalkDir(filesystem, root, walker)
	return vulnerabilities, err
}
