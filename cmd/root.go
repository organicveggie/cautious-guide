/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/apex/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	flagNameVerbose = "verbose"

	defaultVerbose = false
)

var (
	cfgFile string
	verbose bool

	// rootCmd represents the base command when called without any subcommands
	rootCmd = &cobra.Command{
		Use:   "cautious-guide",
		Short: "Identify problematic media files",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application.`,
		Args: cobra.ExactArgs(1),
		RunE: run,
	}

	titleRegEx = regexp.MustCompile("[[:space:]]+title")
)

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.cautious-guide.yaml)")
	rootCmd.PersistentFlags().BoolVar(&verbose, flagNameVerbose, false, "print more information")

	viper.BindPFlag(flagNameVerbose, rootCmd.PersistentFlags().Lookup(flagNameVerbose))
	viper.SetDefault(flagNameVerbose, defaultVerbose)
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".cautious-guide" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigType("yaml")
		viper.SetConfigName(".cautious-guide")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

type execContext = func(name string, arg ...string) *exec.Cmd

func run(cmd *cobra.Command, args []string) error {
	if viper.GetBool(flagNameVerbose) {
		log.SetLevel(log.DebugLevel)
	}

	rootPath := args[0]

	fileNames := make([]string, 0)
	filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Errorf("Error walking directory %q: %v", path, err)
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, "mp4") {
			return nil
		}
		fileNames = append(fileNames, path)
		return nil
	})

	log.Infof("Found %d files", len(fileNames))

	for _, f := range fileNames {
		title, err := getMediaTitle(exec.Command, f)
		if err != nil {
			return err
		}
		if len(title) > 0 {
			log.Info(f)
			log.Infof("Title: %s", title)
		}
	}

	return nil
}

func getMediaTitle(cmdContext execContext, fileName string) (title string, err error) {
	// c := cmdContext("/usr/bin/mediainfo", "--Output=\"General;%%Title%%\"", fileName)
	c := cmdContext("/usr/bin/ffprobe", fileName)
	log.Debugf(c.String())

	var out bytes.Buffer
	c.Stdout = &out
	c.Stderr = &out
	if err = c.Run(); err != nil {
		return title, fmt.Errorf("error running /usr/bin/ffprobe for file %q: %w",
			fileName, err)
	}

	lines := strings.Split(out.String(), "\n")
	for _, txt := range lines {
		if titleRegEx.MatchString(txt) {
			titleData := strings.Split(txt, ":")
			return strings.TrimSpace(titleData[1]), nil
		}
	}

	return title, nil
}
