// Package cli provides the apfs command-line interface. All cobra/viper
// wiring lives here; parsing logic lives in pkg/apfs and pkg/disk.
//
// Configuration precedence: flag > APFS_* environment variable > config file
// (~/.config/apfs/config.yaml, optional).
//
// SOURCE_DATE_EPOCH is the one deliberate exception, resolved as
// --source-date-epoch > SOURCE_DATE_EPOCH > APFS_SOURCE_DATE_EPOCH > config
// file. The bare, unprefixed variable is the ecosystem standard that build
// systems set, so a stale APFS_ value in a shell profile must not defeat it.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v2/internal/tools"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// globalOptions are the persistent flags shared by all commands, resolved
// through viper so environment variables and the config file apply.
type globalOptions struct {
	Output           string // text | json
	Quiet            bool
	Verbose          bool
	Volume           string // index, name or UUID
	Password         string
	PasswordStdin    bool
	RecoveryPassword string
	Offset           int64
	// SourceDateEpoch is the fixed build timestamp for reproducible output. The
	// zero value means unset, leaving each writer to apply its own default.
	SourceDateEpoch time.Time
	// TempDir is where the scratch file for a build goes. Empty means beside
	// the output, which is the safer default: the system temporary directory is
	// often small, and on many Linux images it is RAM-backed.
	TempDir string
}

var opts globalOptions

var rootCmd = &cobra.Command{
	Use:   "apfs",
	Short: "Read, extract and build Apple File System (APFS) and HFS+ disk images",
	Long: `A cross-platform, self-contained toolkit for Apple disk images. It reads
APFS and HFS+ file systems directly from DMGs (zlib, bzip2, ADC, LZFSE or LZMA
compressed), GPT- or Apple-Partition-Map raw images, or bare containers —
without mounting and without macOS — and can also build and repack DMGs.

Read commands:
  info     Container and volume summary (text or JSON)
  list     List directory contents (recursive, JSON lines)
  cat      Write file contents to stdout, for pipelines
  extract  Extract files/directories to the local file system
  inspect  Low-level structural inspection (container walk, blocks, B-trees)
  mount    Mount read-only via FUSE (Linux and macOS)

Write commands:
  pack     Build a DMG from a directory (HFS+), or repack a DMG losslessly
  create   Format an empty HFS+ or APFS volume in a new DMG

Images are auto-detected by content; every command takes the image as its
first argument. Data goes to stdout, diagnostics and progress to stderr.

Configuration precedence: flag > APFS_<FLAG> environment variable >
~/.config/apfs/config.yaml.

Reproducible output: create, pack and snapshot create produce byte-identical
images for identical input, so a built image can be content-addressed and
compared by hash. Set --source-date-epoch (or SOURCE_DATE_EPOCH) to pin the
build timestamp and clamp source modification times to it, and --uuid to pin
the volume identity. SOURCE_DATE_EPOCH resolves as --source-date-epoch >
SOURCE_DATE_EPOCH > APFS_SOURCE_DATE_EPOCH > config file: the bare variable is
the ecosystem standard, so it outranks the APFS_ form.

Exit codes:
  0 success        3 unrecognized image     5 unsupported on this platform
  1 error          4 authentication needed  6 partial result
  2 usage error       or failed`,
	Version:           tools.Version(),
	SilenceUsage:      true,
	SilenceErrors:     true,
	DisableAutoGenTag: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		return resolveGlobalOptions(cmd)
	},
}

func init() {
	flags := rootCmd.PersistentFlags()
	flags.StringP("output", "o", "text", "output format: text or json")
	flags.BoolP("quiet", "q", false, "suppress progress and non-essential messages")
	flags.Bool("verbose", false, "verbose diagnostics on stderr")
	flags.StringP("volume", "v", "", "volume to operate on: index, name, UUID or role (e.g. system, role:data) (default: first)")
	flags.StringP("password", "p", "", "password for encrypted volumes")
	flags.Bool("password-stdin", false, "read the password from standard input")
	flags.String("recovery-password", "", "recovery password for encrypted volumes")
	flags.Int64("offset", 0, "byte offset of the container in the image (expert; overrides detection)")
	flags.String("source-date-epoch", "", "fixed build timestamp (decimal seconds since 1970 UTC) for reproducible output")
	flags.String("temp-dir", "", "directory for the scratch file used while building an image (default: beside the output)")

	rootCmd.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return withCode(ExitUsage, err)
	})

	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(catCmd)
	rootCmd.AddCommand(extractCmd)
	rootCmd.AddCommand(packCmd)
	rootCmd.AddCommand(createCmd)
	rootCmd.AddCommand(inspectCmd)
	rootCmd.AddCommand(mountCmd)
	rootCmd.AddCommand(snapshotCmd)
}

// resolveGlobalOptions binds flags into viper and resolves the effective
// configuration from flags, APFS_* environment variables and the optional
// config file.
func resolveGlobalOptions(cmd *cobra.Command) error {
	v := viper.New()
	v.SetEnvPrefix("APFS")
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
	v.AutomaticEnv()

	if err := v.BindPFlags(cmd.Root().PersistentFlags()); err != nil {
		return err
	}

	if home, err := os.UserHomeDir(); err == nil {
		v.SetConfigFile(filepath.Join(home, ".config", "apfs", "config.yaml"))
		// The config file is optional; only complain if it exists but is invalid
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(*os.PathError); !ok && !os.IsNotExist(err) {
				if _, notFound := err.(viper.ConfigFileNotFoundError); !notFound {
					return fmt.Errorf("unable to read config file: %w", err)
				}
			}
		}
	}

	opts = globalOptions{
		Output:           v.GetString("output"),
		Quiet:            v.GetBool("quiet"),
		Verbose:          v.GetBool("verbose"),
		Volume:           v.GetString("volume"),
		Password:         v.GetString("password"),
		PasswordStdin:    v.GetBool("password-stdin"),
		RecoveryPassword: v.GetString("recovery-password"),
		Offset:           v.GetInt64("offset"),
		TempDir:          v.GetString("temp-dir"),
	}

	// SOURCE_DATE_EPOCH deliberately departs from the flag > APFS_<FLAG> >
	// config order used by everything else: the bare, unprefixed variable is the
	// ecosystem standard that build systems set, and a stale APFS_ value left in
	// a shell profile must not defeat it.
	raw := ""
	if f := cmd.Root().PersistentFlags().Lookup("source-date-epoch"); f != nil && f.Changed {
		raw = f.Value.String()
	} else if env := os.Getenv("SOURCE_DATE_EPOCH"); env != "" {
		raw = env
	} else {
		raw = v.GetString("source-date-epoch")
	}
	if raw != "" {
		epoch, err := parseSourceDateEpoch(raw)
		if err != nil {
			return err
		}
		opts.SourceDateEpoch = epoch
	}

	switch opts.Output {
	case "text", "json":
	default:
		return usageErrorf("invalid --output %q: must be text or json", opts.Output)
	}

	if opts.PasswordStdin {
		password, err := readPasswordFromStdin()
		if err != nil {
			return fmt.Errorf("unable to read password from stdin: %w", err)
		}
		opts.Password = password
	}

	return nil
}

func readPasswordFromStdin() (string, error) {
	var password string
	if _, err := fmt.Fscanln(os.Stdin, &password); err != nil {
		return "", err
	}
	return password, nil
}

// exactArgs is like cobra.ExactArgs but returns a usage-coded error.
func exactArgs(n int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) != n {
			return usageErrorf("expected %s (got %d arguments)", usage, len(args))
		}
		return nil
	}
}

// rangeArgs is like cobra.RangeArgs but returns a usage-coded error.
func rangeArgs(min, max int, usage string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < min || len(args) > max {
			return usageErrorf("expected %s (got %d arguments)", usage, len(args))
		}
		return nil
	}
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return exitCodeFor(err)
	}
	return ExitOK
}
