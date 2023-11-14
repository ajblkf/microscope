package pkgscan

import "io"
import "io/fs"
import "bufio"
import "strings"

const APKPackageList = "lib/apk/db/installed"

type APKListReader struct {
	reader *bufio.Reader
	line string
}

func NewAPKListReader (list io.Reader) *APKListReader {
	reader := &APKListReader {
		reader: bufio.NewReader(list),
	}
	reader.nextLine()
	return reader
}

func (this *APKListReader) Next () (Package, error) {
	var pack Package
	for this.line != "" {
		switch this.line[0] {
		case 'P':
			pack.Name = this.line[2:]
		case 'V':
			pack.Version,
			_, _ = strings.Cut(this.line[2:], "-")
			
			pack.Version,
			pack.Release, _ = strings.Cut(this.line[2:], "-")
			pack.Release = pack.Release[1:]
		}

		err := this.nextLine()
		if err != nil { return pack, err }
	}
	return pack, this.nextLine()
}

func (this *APKListReader) nextLine () error {
	this.line = ""
	for {
		ch, _, err := this.reader.ReadRune()
		if err != nil { return err }
		if ch == '\n' {
			break
		}
		this.line += string(ch)
	}
	return nil
}

func ScanAPK (filesystem fs.FS, database Database) ([]Vulnerability, error) {
	file, err := filesystem.Open(APKPackageList)
	if err != nil { return nil, err }
	defer file.Close()
	return ScanPackageReader(NewAPKListReader(file), database)
}
