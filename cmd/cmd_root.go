package cmd

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/dcadolph/fleetsweeper/internal/logutil"
)

var rootCmd = &cobra.Command{
	Use:   "fleetsweeper",
	Short: "Compare Kubernetes clusters across your fleet",
	Long:  "Fleetsweeper scans multiple Kubernetes clusters and produces a structured comparison report highlighting configuration divergence.",
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		level, _ := cmd.Flags().GetString("log-level")
		log, err := newLogger(level)
		if err != nil {
			return err
		}
		ctx := logutil.WrapLogger(cmd.Context(), log)
		cmd.SetContext(ctx)
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().String("kubeconfig", defaultKubeconfig(), "Path to the kubeconfig file.")
	rootCmd.PersistentFlags().Bool("pretty", false, "Pretty-print JSON output.")
	rootCmd.PersistentFlags().String("log-level", "warn", "Log level (debug, info, warn, error).")

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd)
}

// defaultKubeconfig returns the default kubeconfig path from the environment
// or ~/.kube/config.
func defaultKubeconfig() string {
	if v := os.Getenv("KUBECONFIG"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".kube", "config")
}

// newLogger creates a zap logger writing to stderr at the given level.
func newLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zapcore.WarnLevel
	}
	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Encoding:         "console",
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zap.NewProductionEncoderConfig(),
	}
	return cfg.Build()
}
