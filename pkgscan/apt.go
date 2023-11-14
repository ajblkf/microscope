package pkgscan

import "io"
import "io/fs"
import "bufio"
import "strings"

const DPKGPackageList = "/var/lib/dpkg/status"

type DPKGListReader struct {
	reader *bufio.Reader
	line string
}

func NewDPKGListReader (list io.Reader) *DPKGListReader {
	reader := &DPKGListReader {
		reader: bufio.NewReader(list),
	}
	reader.nextLine()
	return reader
}

func (this *DPKGListReader) Next () (Package, error) {
	var pack Package
	for this.line != "" {
		key, value, _ := strings.Cut(this.line, ": ")
	
		switch key {
		case "Package":
			pack.Name = value
		case "Version":
			pack.Version, pack.Release, _ = strings.Cut(value, "-")
		}

		err := this.nextLine()
		if err != nil { return pack, err }
	}
	return pack, this.nextLine()
}

func (this *DPKGListReader) nextLine () error {
	line, err := this.reader.ReadString('\n')
	this.line = line
	if len(this.line) > 0 {
		this.line = this.line[:len(this.line)]
	}
	return err
}

func ScanAPT (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	file, err := filesystem.Open(DPKGPackageList)
	if err != nil { return nil, err }
	defer file.Close()
	return ScanPackageReader(NewDPKGListReader(file), database)
}
