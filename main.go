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
	log "github.com/Sirupsen/logrus"
	"github.com/mattn/go-colorable"
	flag "github.com/spf13/pflag"
)

var (
	// This is our Yara scanner.
	scanner Scanner
	// This is a flag to enable debug logging.
	debug *bool
	// This is a flag to determine whether to execute as a permanent agent or not.
	// In case this is false, we just scan active processes and exit.
	daemon *bool
	// This is a flag to enable remote reporting to API server.
	report *bool
	// This is a folder to be scanned instead of the default.
	customFileSystemRoot *string
	// This is a file or folder path containing the Yara rules to use.
	customRulesPath *string
	// This is a flag to disable process scanning.
	// noProcessScan *bool
	// This is a flag to disable filesystem scanning.
	noFileSystemScan *bool
)

func initArguments() {
	debug = flag.Bool("debug", false, "Enable debug logs")
	customFileSystemRoot = flag.String("folder", "", "Specify a particular folder to be scanned (overrides the default full filesystem)")
	customRulesPath = flag.String("rules", "", "Specify a particular path to a file or folder containing the Yara rules to use")
	noFileSystemScan = flag.Bool("no-filesystem", false, "Disable scanning of filesystem")
	flag.Parse()
}

func initLogging() {
	log.SetFormatter(&log.TextFormatter{ForceColors: true})
	log.SetOutput(colorable.NewColorableStdout())

	if *debug {
		log.SetLevel(log.DebugLevel)
	}
}


// This function contains just the preliminary actions.
func init() {
	// Parse arguments.
	initArguments()
	// Initialize debugging.
	initLogging()

	log.Debug("This machine is identified as ", config.MachineID)
	log.Debug("URLBaseDomain: ", config.URLBaseDomain)
	log.Debug("URLToRules: ", config.URLToRules)
	log.Debug("URLToRegister: ", config.URLToRegister)
	log.Debug("URLToDetection: ", config.URLToDetection)
	log.Debug("URLToAutorun: ", config.URLToAutorun)
}

func main() {
	// Initialize the Yara scanner.
	err := scanner.Init()
	if err != nil {
		scanner.Available = false
	} else {
		scanner.Available = true
	}
	defer scanner.Close()

	// We store here the list of detections.
	var detections []*Detection

	// Now we do a scan of the file system if required.
	if *noFileSystemScan == false {
		log.Info("Scanning the filesystem (this can take several minutes)...")
		detections = append(detections, filesystemScan()...)
	}

	// Now we tell the results.
	if len(detections) > 0 {
		log.Error("Some malicious artifacts have been detected on this system:")
		for _, detection := range detections {
			log.Error("Found detection for ", detection.Signature)
		}
	} else {
		log.Info("GOOD! Nothing detected!")
	}
}
