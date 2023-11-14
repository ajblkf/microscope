package pmdetect

import "fmt"
import "io/fs"

// This file is incomplete

// PackageManager represents a list of common package managers
type PackageManager int; const (
	// OS native
	PmAPT PackageManager = iota
	PmAPK
	PmDNF
	PmPacman
	PmXBPS

	// Sandboxed, distro agnostic
	PmFlatpak
	PmSnap

	pmCap // Must always be at the end of the list!
)

// ExistsOn returns whether or not the given package manager exists on the
// system. Root is the root filesystem of the system being analyzed.
func (pm PackageManager) ExistsOn (root fs.FS) bool {
	switch pm {
	case PmAPT:     return fileExists(root, "etc/apt/sources.list") ||
				fileExists(root, "etc/apt/sources.list.d")
	case PmAPK:     return fileExists(root, "etc/apk/repositories")
	case PmDNF:     return fileExists(root, "etc/yum.repos.d")
	case PmPacman:	return fileExists(root, "etc/pacman.conf") ||
				fileExists(root, "etc/pacman.d")
	case PmXBPS:    return fileExists(root, "usr/share/xbps.d")
	case PmFlatpak: return fileExists(root, "var/lib/flatpak")
	case PmSnap:    return fileExists(root, "etc/snap")
	default: return false
	}
}

func (pm PackageManager) String () string {
	switch pm {
	case PmAPT:     return "APT"
	case PmAPK:     return "APK"
	case PmDNF:     return "DNF"
	case PmPacman:  return "Pacman"
	case PmXBPS:    return "XBPS"
	case PmFlatpak: return "Flatpak"
	case PmSnap:    return "Snap"
	default: return fmt.Sprintf("pmdetect.PackageManager(%d)", pm)
	}
}

// Detect returns a list of package managers being used on the system. Root is
// the root filesystem of the system being analyzed.
func Detect (root fs.FS) []PackageManager {
	var pms []PackageManager
	for pm := PmAPT; pm < pmCap; pm ++ {
		if pm.ExistsOn(root) {
			pms = append(pms, pm)
		}
	}
	return pms
}

func fileExists (filesystem fs.FS, name string) bool {
	file, err := filesystem.Open(name)
	if err != nil { return false}
	file.Close()
	return true
}
