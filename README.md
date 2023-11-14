# microscope

Microscope is a utility that aids in identifying vulnerable or unwanted software
installed on a system. It is designed for easy integration into a CI/CD
pipeline, and has the ability to do things like scan docker containers while
they aren't even running. Simply obtain a database of files/packages you want to
scan for, and Microscope will do the rest.

## Installing

### Building from source

If you have Go installed, run these commands:

```
git clone github.com/ajblkf/microscope
cd microscope
go install ./cmd/microscope
```

This will install the `microscope` command locally. In order to have it system
wide, you can move it to `/usr/local/sbin` or a similar location.

### Get a binary

Microscope is distributed as a statically linked binary through the releases
tab on this repository. You can save it as `/usr/local/sbin/microscope` to get
the `microscope` command system-wide.

## Usage

### Command line options

- `-pkgdb FILE`: Specify a deny list of unwanted packages
- `-db FILE`: Specify a deny list of unwanted files
- `-files FILES...`: Recursively scan a list of files or directories
- `-pkg`: Scan packages installed on the system
- `-npm PROJECT-DIRECTORY`: Scan dependencies of an NPM project
- `-docker-files CONTAINER FILES...`: Scan files installed in a docker container
- `-docker-pkg CONTAINER`: Scan packages installed in a docker container
- `-archive-files ARCHIVE FILES...`: Scan files contained in an archive
- `-archive-pkg ARCHIVE`: Scan packages installed in an archive of a filesystem
- `-docker-npm CONTAINER PROJECT-DIRECTORY`: Scan dependencies of an NPM project
  inside of a docker container

### Database file structure

#### Package deny list
The package deny list is a CSV file with two columns: a package identifier, and
a reason why the package is in the list. The package identifier is formatted as
follows:

```
NAME-VERSION-RELEASE:REPOSITORY
```

If any of these parts are left blank, they will match anything.

Here is a sample deny list that detects Firefox version 100, which is vulnerable
to CVE-2022-1802:

```
firefox-100.0-:, Vulnerable to CVE-2022-1802
firefox-100.0.1-:, Vulnerable to CVE-2022-1802
firefox-100.0.2-:, Vulnerable to CVE-2022-1802
```

### File deny list
The file deny list is a CSV file with two columns: a hexadecimal encoded sha256
sum of the file to detect, and a reason why the file is in the list.

Here is a sample deny list that detects files consisting of "hello\n":

```
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03, Some reason
```

## Integrating with Jenkins

See [docs/jenkins.md](docs/jenkins.md).
