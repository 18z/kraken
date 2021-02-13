// Kraken
// Copyright (C) 2016-2020  Claudio Guarnieri
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package main

import (
	"os"
	"path/filepath"

	"github.com/botherder/go-savetime/files"
	"github.com/botherder/go-savetime/hashes"
)

// Detection contains the information to report a Yara detection.
type Detection struct {
	Type      string `json:"type"`
	ImagePath string `json:"image_path"`
	ImageName string `json:"image_name"`
	MD5       string `json:"md5"`
	SHA1      string `json:"sha1"`
	SHA256    string `json:"sha256"`
	ProcessID int32  `json:"process_id"`
	Signature string `json:"signature"`
}

// NewDetection instantiates a new Detection.
func NewDetection(recordType, imagePath, imageName, signature string, pid int32) *Detection {
	md5, _ := hashes.FileMD5(imagePath)
	sha1, _ := hashes.FileSHA1(imagePath)
	sha256, _ := hashes.FileSHA256(imagePath)

	return &Detection{
		Type:      recordType,
		ImagePath: imagePath,
		ImageName: imageName,
		MD5:       md5,
		SHA1:      sha1,
		SHA256:    sha256,
		ProcessID: pid,
		Signature: signature,
	}
}

// Backup will keep a copy
func (d *Detection) Backup() error {
	if _, err := os.Stat(d.ImagePath); err != nil {
		return err
	}

	dstPath := filepath.Join(StorageFiles, d.SHA1)
	if _, err := os.Stat(dstPath); os.IsNotExist(err) {
		err = files.Copy(d.ImagePath, dstPath)
		if err != nil {
			return err
		}
	}

	return nil
}

