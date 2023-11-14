package pkgscan

import "io"
import "path"
import "encoding/json"

type NPMListReader struct {
	list []Package
}

type npmPackageList struct {
	Packages map[string] npmPackageEntry `json:"packages"`
}

type npmPackageEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func NewNPMListReader (packageLock io.Reader) (*NPMListReader, error) {
	decoder := json.NewDecoder(packageLock)
	list := npmPackageList { }
	err := decoder.Decode(&list)
	if err != nil { return nil, err }

	reader := &NPMListReader {
		list: make([]Package, len(list.Packages)),
	}
	index := 0
	for where, entry := range list.Packages {
		pkg := Package {
			Name:    entry.Name,
			Version: entry.Version,
		}
		
		if pkg.Name == "" {
			pkg.Name = path.Base(where)
		}
		
		reader.list[index] = pkg
		index ++
	}
	
	return reader, nil
}

func (this *NPMListReader) Next () (Package, error) {
	if len(this.list) < 1 {
		return Package { }, io.EOF
	}
	
	pkg := this.list[0]
	this.list = this.list[1:]
	return pkg, nil
}

func ScanNPM (packageLock io.Reader, database Database) ([]Vulnerability, error) {
	reader, err := NewNPMListReader(packageLock)
	if err != nil { return nil, err }
	return ScanPackageReader(reader, database)
}
