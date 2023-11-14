package localdb

import "io"
import "fmt"
import "hash"
import "io/fs"
import "errors"
import "encoding/hex"
import "encoding/csv"
import "crypto/sha256"
import "github.com/ajblkf/microscope/binscan"
import "github.com/ajblkf/microscope/pkgscan"

type packageEntry struct {
	pkgscan.Package
	reason string
}

func (entry packageEntry) matches (pkg pkgscan.Package) bool {
	return (entry.Name == pkg.Name) &&
		(entry.Version    == "" || entry.Version    == pkg.Version) &&
		(entry.Release    == "" || entry.Release    == pkg.Release) &&
		(entry.Repository == "" || entry.Repository == pkg.Repository)
}

type Database struct {
	hash hash.Hash
	Files    map[string] string
	Packages map[string] []packageEntry
}

func (this *Database) ReadFileDb (input io.Reader) error {
	if this.Files == nil { this.Files = make(map[string] string) }
	return readMap(input, this.Files)
}

func (this *Database) ReadPackageDb (input io.Reader) error {
	if this.Packages == nil { this.Packages = make(map[string] []packageEntry) }
	
	reader := csv.NewReader(input)
	line := 0
	for {
		line ++
		row, err := reader.Read()
		if err == io.EOF { break }
		if err != nil { return err }
		if len(row) != 2 {
			return errors.New(fmt.Sprintf (
				"%v: wrong record count", line))
		}

		pkg := pkgscan.ParsePackage(row[0])
		this.Packages[pkg.Name] = append(this.Packages[pkg.Name], packageEntry {
			Package: pkg,
			reason:  row[1],
		})
	}
	return nil
}

func readMap (input io.Reader, destination map[string] string) error {	
	reader := csv.NewReader(input)
	line := 0
	for {
		line ++
		row, err := reader.Read()
		if err == io.EOF { break }
		if err != nil { return err }
		if len(row) != 2 {
			return errors.New(fmt.Sprintf (
				"%v: wrong record count", line))
		}
		destination[row[0]] = row[1]
	}
	return nil
}

func (this *Database) CheckFile (filesystem fs.FS, path string) (*binscan.Vulnerability, error) {
	this.ensure()
	if this.Files == nil { return nil, nil }

	file, err := filesystem.Open(path)
	if err != nil { return nil, err }
	defer file.Close()

	this.hash.Reset()
	_, err = io.Copy(this.hash, file)
	if err != nil { return nil, err }

	hashString := hex.EncodeToString(this.hash.Sum(nil))
	reason, vulnerable := this.Files[hashString]
	if vulnerable {
		return &binscan.Vulnerability {
			Name:   path,
			Hash:   hashString,
			Source: "Local database",
			Reason: reason,
		}, nil
	}

	return nil, nil
}

func (this *Database) CheckPackage (pkg pkgscan.Package) (*pkgscan.Vulnerability, error) {
	this.ensure()
	if this.Packages == nil { return nil, nil }
	
	versions, vulnerable := this.Packages[pkg.Name]
	if !vulnerable { return nil, nil }
	for _, entry := range versions {
		if entry.matches(pkg) {
			return &pkgscan.Vulnerability {
				Package: pkg,
				Source:  "Local database",
				Reason:  entry.reason,
			}, nil
		}
	}

	return nil, nil
}

func (this *Database) ensure () {
	if this.hash != nil { return }
	this.hash = sha256.New()
}
