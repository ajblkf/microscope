package pkgscan

import "os"
import "io"
import "io/fs"
import "strings"
import "database/sql"
import _ "github.com/glebarez/go-sqlite"

const DNFPackageList = "var/cache/dnf/packages.db"

type DNFListReader struct {
	rows *sql.Rows
}

func NewDNFListReader (list *sql.Rows) *DNFListReader {
	reader := &DNFListReader {
		rows: list,
	}
	reader.rows.Next()
	return reader
}

func (this *DNFListReader) Next () (Package, error) {
	if !this.rows.Next() { return Package { }, io.EOF }

	var rawName string
	err := this.rows.Scan(&rawName)
	if err != nil { return Package { }, err }
	return parseDNFGarbageNonsense(rawName), nil
}

func ScanDNF (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	// extract sqlite file from filesystem in order to read it
	file, err := extractToTemp(filesystem, DNFPackageList)
	if err != nil { return nil, err }
	name := file.Name()
	file.Close()
	defer os.Remove(name)

	// "connect" to database
	db, err := sql.Open("sqlite", file.Name())
	if err != nil { return nil, err }
	defer db.Close()

	// get rows
	rows, err := db.Query("select * from installed;")
	if err != nil { return nil, err }

	// scan
	return ScanPackageReader(NewDNFListReader(rows), database)
}

func extractToTemp (filesystem fs.FS, name string) (*os.File, error) {
	file, err := filesystem.Open(DNFPackageList)
	if err != nil { return nil, err }
	defer file.Close()

	temp, err := os.CreateTemp("", "microscope_*")
	if err != nil { return nil, err }

	_, err = io.Copy(temp, file)
	if err != nil { return nil, err }
	_, err = temp.Seek(0, io.SeekStart)
	if err != nil { return nil, err }
	
	return temp, nil
}

func parseDNFGarbageNonsense (input string) Package {
	// this part is literally just to separate the name and the
	// version/arch mash

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

	pack.Version, _, _ = strings.Cut(pack.Version, "-")

	// take arch off of version
	// index := strings.LastIndex(pack.Version, ".")
	// if index >= 0 {
		// pack.Version = pack.Version[:index]
	// }

	return pack
}
