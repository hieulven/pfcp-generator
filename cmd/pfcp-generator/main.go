package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"pfcp-generator/internal/config"
	"pfcp-generator/internal/network"
	"pfcp-generator/internal/pcap"
	"pfcp-generator/internal/session"
	"pfcp-generator/internal/stats"
	"pfcp-generator/pkg/types"
)

var (
	version   = "1.0.0"
	cfgFile   string
	dryRun    bool
	statsOnly bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "pfcp-generator",
		Short: "PFCP Message Generator - Replay PFCP messages from pcap to UPF",
		Long: `A Go-based tool that acts as an SMF node, reading PFCP messages from a pcap
file, modifying session-specific identifiers, and replaying them to a target UPF.`,
		Version: version,
		RunE:    run,
	}

	// Configuration file
	rootCmd.Flags().StringVar(&cfgFile, "config", "", "Configuration file path (default: config.yaml)")

	// CLI overrides
	rootCmd.Flags().String("pcap", "", "Input PCAP file path")
	rootCmd.Flags().String("smf-ip", "", "Local SMF IP address")
	rootCmd.Flags().String("upf-ip", "", "Target UPF IP address")
	rootCmd.Flags().Int("upf-port", 0, "Target UPF port")
	rootCmd.Flags().String("ue-pool", "", "UE IPv4 address pool (CIDR)")
	rootCmd.Flags().Uint64("seid-start", 0, "Starting SEID value")
	rootCmd.Flags().String("seid-strategy", "", "SEID allocation strategy (sequential|random)")
	rootCmd.Flags().Int("message-interval", -1, "Delay between messages in ms")
	rootCmd.Flags().Int("timeout", 0, "Response timeout in ms")
	rootCmd.Flags().Int("max-retries", -1, "Max retransmission attempts")
	rootCmd.Flags().String("log-level", "", "Log level (debug|info|warn|error)")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Parse and modify only, do not send to UPF")
	rootCmd.Flags().BoolVar(&statsOnly, "stats-only", false, "Show pcap statistics only, do not replay")
	rootCmd.Flags().Bool("cleanup", false, "Delete all sessions on exit")
	rootCmd.Flags().Bool("no-association", false, "Disable PFCP Association Setup")
	rootCmd.Flags().Bool("strip-ipv6", true, "Strip IPv6 from UE IP Address IEs")
	rootCmd.Flags().Int("repeat", 1, "Number of replay iterations (0 = infinite)")
	rootCmd.Flags().Int("repeat-interval", 0, "Delay between repeat iterations in ms")

	rootCmd.Flags().Int("source-ports", 0, "Number of source UDP ports (default 1)")
	rootCmd.Flags().Bool("strip-vendor-ies", true, "Strip vendor-specific IEs (type >= 32768)")

	// Stress test flags
	rootCmd.Flags().Bool("stress", false, "Enable high-performance stress test mode")
	rootCmd.Flags().Int("tps", 0, "Target transactions per second (stress mode)")
	rootCmd.Flags().Int("active-sessions", 0, "Max concurrent active sessions (stress mode)")
	rootCmd.Flags().Int("duration", 0, "Test duration in seconds (stress mode, 0=unlimited)")
	rootCmd.Flags().String("log-file", "", "Log file path (auto-set to pfcp-generator.log in stress mode)")

	// Bind CLI flags to viper
	v := viper.New()
	bindFlag(v, rootCmd, "pcap", "input.pcap_file")
	bindFlag(v, rootCmd, "smf-ip", "smf.address")
	bindFlag(v, rootCmd, "upf-ip", "upf.address")
	bindFlag(v, rootCmd, "upf-port", "upf.port")
	bindFlag(v, rootCmd, "ue-pool", "session.ue_ip_pool")
	bindFlag(v, rootCmd, "seid-start", "session.seid_start")
	bindFlag(v, rootCmd, "seid-strategy", "session.seid_strategy")
	bindFlag(v, rootCmd, "message-interval", "timing.message_interval_ms")
	bindFlag(v, rootCmd, "timeout", "timing.response_timeout_ms")
	bindFlag(v, rootCmd, "max-retries", "timing.max_retries")
	bindFlag(v, rootCmd, "log-level", "logging.level")
	bindFlag(v, rootCmd, "cleanup", "session.cleanup_on_exit")
	bindFlag(v, rootCmd, "strip-ipv6", "session.strip_ipv6")
	bindFlag(v, rootCmd, "repeat", "input.repeat_count")
	bindFlag(v, rootCmd, "repeat-interval", "timing.repeat_interval_ms")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func bindFlag(v *viper.Viper, cmd *cobra.Command, flagName, configKey string) {
	_ = v.BindPFlag(configKey, cmd.Flags().Lookup(flagName))
}

func run(cmd *cobra.Command, args []string) error {
	// Load configuration
	v := viper.New()
	config.SetDefaults(v)

	// Load config file
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
	}

	if err := v.ReadInConfig(); err != nil {
		if cfgFile != "" {
			return fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found is OK if using CLI flags
		log.Debug("No config file found, using defaults and CLI flags")
	}

	// Bind CLI flags (override config file values)
	bindViperFlags(v, cmd)

	// Handle --no-association flag
	if noAssoc, _ := cmd.Flags().GetBool("no-association"); noAssoc {
		v.Set("association.enabled", false)
	}

	cfg, err := config.LoadWithViper(v)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// In stress mode, auto-redirect logs to file to keep terminal clean for dashboard
	if cfg.Stress.Enabled && cfg.Logging.File == "" {
		cfg.Logging.File = "pfcp-generator.log"
	}

	// Setup logging
	setupLogging(cfg)

	fmt.Printf("PFCP Message Generator v%s\n", version)
	fmt.Println("==============================")
	fmt.Print(cfg.Summary())
	fmt.Println()

	// Stats-only mode
	if statsOnly {
		return showStats(cfg)
	}

	// Validate config
	if !dryRun {
		if err := cfg.Validate(); err != nil {
			return err
		}
	} else {
		// In dry-run mode, skip network-related validation
		if cfg.Input.PcapFile == "" {
			return fmt.Errorf("input.pcap_file must be specified")
		}
	}

	// Parse PCAP
	parser := pcap.NewParser()
	parseResult, err := parser.ParseWithMappings(cfg.Input.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to parse pcap: %w", err)
	}

	messages := parseResult.Messages

	if len(messages) == 0 {
		return fmt.Errorf("no PFCP request messages found in pcap file")
	}

	// Validate pcap has establishment requests
	if err := parser.ValidateHasEstablishment(messages); err != nil {
		return err
	}

	fmt.Printf("Found %d PFCP request messages\n\n", len(messages))

	if dryRun {
		fmt.Println("Dry-run mode: skipping network transmission")
		return nil
	}

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.WithField("signal", sig).Info("Received shutdown signal")
		cancel()
	}()

	// Create network client pool
	pool, err := network.NewUDPClientPool(cfg.SMF.Address, cfg.SMF.Port, cfg.UPF.Address, cfg.UPF.Port, cfg.SMF.SourcePorts)
	if err != nil {
		return fmt.Errorf("failed to create UDP client pool: %w", err)
	}
	defer pool.Close()

	if pool.Size() > 1 {
		log.WithField("ports", pool.LocalAddrs()).Infof("UDP client pool started (%d ports)", pool.Size())
	} else {
		log.WithField("local_addr", pool.LocalAddrs()[0]).Info("UDP client started")
	}

	// Create receiver with dynamic buffer size for stress mode
	recvBufSize := 1000
	if cfg.Stress.Enabled && cfg.Stress.TPS > 0 {
		recvBufSize = cfg.Stress.TPS * 2
		if recvBufSize < 50000 {
			recvBufSize = 50000
		}
	}
	receiver := network.NewMultiReceiver(pool.Conns(), recvBufSize)
	receiver.Start(ctx)

	// Create transaction tracker
	tracker := network.NewTransactionTracker(pool, cfg.Timing.ResponseTimeoutMs, cfg.Timing.MaxRetries)
	tracker.StartTimeoutMonitor(ctx)

	// Create stats collector and reporter
	statsCollector := stats.NewCollector()
	reporter := stats.NewReporter(statsCollector, cfg.Stats.ReportIntervalSec, cfg.Stats.ExportFile)

	// Start periodic report only for normal mode (stress mode uses live dashboard)
	if cfg.Stats.Enabled && !cfg.Stress.Enabled {
		reporter.StartPeriodicReport(ctx)
	}

	// Create session manager
	mgr, err := session.NewManager(cfg, pool, receiver, tracker, statsCollector)
	if err != nil {
		return fmt.Errorf("failed to create session manager: %w", err)
	}

	// Register original SEID mappings from pcap
	if len(parseResult.SEIDMappings) > 0 {
		mgr.SetSEIDMappings(parseResult.SEIDMappings)
	}

	// Start response handler once (shared across all replay iterations)
	mgr.StartResponseHandler(ctx)

	// Dispatch to stress mode or normal mode
	if cfg.Stress.Enabled {
		return runStressMode(ctx, mgr, cfg, messages, parseResult, statsCollector, reporter)
	}

	return runNormalMode(ctx, mgr, cfg, messages, reporter)
}

func runStressMode(ctx context.Context, mgr *session.Manager, cfg *config.Config, messages []types.RawPFCPMessage, parseResult *pcap.ParseResult, statsCollector *stats.Collector, reporter *stats.Reporter) error {
	// Build replay plan from pcap messages
	plan, err := session.BuildReplayPlan(messages, parseResult.SEIDMappings)
	if err != nil {
		return fmt.Errorf("failed to build replay plan: %w", err)
	}

	fmt.Printf("Stress test mode: %d templates, %d msgs/session\n", len(plan.Templates), plan.MessagesPerSession)
	fmt.Printf("Target: %d TPS, %d active sessions", cfg.Stress.TPS, cfg.Stress.ActiveSessions)
	if cfg.Stress.DurationSec > 0 {
		fmt.Printf(", %d seconds\n", cfg.Stress.DurationSec)
	} else {
		fmt.Println(", unlimited duration")
	}
	if cfg.Logging.File != "" {
		fmt.Printf("Logs: %s\n", cfg.Logging.File)
	}
	fmt.Println()

	// Start live dashboard
	reporter.SetTargetTPS(cfg.Stress.TPS)
	stopDashboard := reporter.StartLiveDashboard(ctx)

	duration := time.Duration(cfg.Stress.DurationSec) * time.Second

	if err := mgr.ReplayStress(ctx, plan, float64(cfg.Stress.TPS), cfg.Stress.ActiveSessions, duration); err != nil {
		if ctx.Err() != nil {
			log.Info("Stress test interrupted by shutdown")
		} else {
			log.WithError(err).Error("Stress test failed")
		}
	}

	// Stop dashboard and render final state
	stopDashboard()
	reporter.PrintFinalDashboard()

	// Cleanup
	if cfg.Session.CleanupOnExit {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		mgr.CleanupSessions(cleanupCtx)
		cleanupCancel()
	}

	if cfg.Stats.Enabled {
		if err := reporter.ExportJSON(); err != nil {
			log.WithError(err).Warn("Failed to export statistics")
		}
	}

	return nil
}

func runNormalMode(ctx context.Context, mgr *session.Manager, cfg *config.Config, messages []types.RawPFCPMessage, reporter *stats.Reporter) error {
	repeatCount := cfg.Input.RepeatCount
	repeatInterval := time.Duration(cfg.Timing.RepeatIntervalMs) * time.Millisecond

	fmt.Println("Sending messages to UPF...")

	for iter := 1; repeatCount == 0 || iter <= repeatCount; iter++ {
		if ctx.Err() != nil {
			log.Info("Replay cancelled")
			break
		}

		if repeatCount != 1 {
			if repeatCount == 0 {
				fmt.Printf("\n[Iteration %d - running indefinitely, Ctrl+C to stop]\n", iter)
			} else {
				fmt.Printf("\n[Iteration %d/%d]\n", iter, repeatCount)
			}
		}

		if err := mgr.Replay(ctx, messages); err != nil {
			if ctx.Err() != nil {
				log.Info("Replay interrupted by shutdown")
				break
			}
			log.WithError(err).Error("Replay failed")
		}

		isLast := repeatCount > 0 && iter >= repeatCount
		if isLast {
			break
		}

		if ctx.Err() != nil {
			break
		}

		// Between iterations: clean up active sessions, reset state, then wait
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		mgr.CleanupSessions(cleanupCtx)
		cleanupCancel()

		mgr.Reset()

		if repeatInterval > 0 {
			select {
			case <-ctx.Done():
			case <-time.After(repeatInterval):
			}
		}
	}

	// Cleanup sessions if configured (after final iteration)
	if cfg.Session.CleanupOnExit {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		mgr.CleanupSessions(cleanupCtx)
		cleanupCancel()
	}

	// Print final statistics
	if cfg.Stats.Enabled {
		reporter.PrintFinalReport()
		if err := reporter.ExportJSON(); err != nil {
			log.WithError(err).Warn("Failed to export statistics")
		}
	}

	return nil
}

func showStats(cfg *config.Config) error {
	parser := pcap.NewParser()
	counts, err := parser.CountMessages(cfg.Input.PcapFile)
	if err != nil {
		return fmt.Errorf("failed to count messages: %w", err)
	}

	fmt.Println("PCAP Message Statistics:")
	total := 0
	for msgType, count := range counts {
		fmt.Printf("  %-40s %d\n", msgType, count)
		total += count
	}
	fmt.Printf("  %-40s %d\n", "Total:", total)
	return nil
}

func setupLogging(cfg *config.Config) {
	level, err := log.ParseLevel(cfg.Logging.Level)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05.000",
	})

	if cfg.Logging.File != "" {
		f, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithError(err).Warn("Failed to open log file, using console only")
		} else {
			log.SetOutput(f)
		}
	}
}

func bindViperFlags(v *viper.Viper, cmd *cobra.Command) {
	if cmd.Flags().Changed("pcap") {
		val, _ := cmd.Flags().GetString("pcap")
		v.Set("input.pcap_file", val)
	}
	if cmd.Flags().Changed("smf-ip") {
		val, _ := cmd.Flags().GetString("smf-ip")
		v.Set("smf.address", val)
	}
	if cmd.Flags().Changed("upf-ip") {
		val, _ := cmd.Flags().GetString("upf-ip")
		v.Set("upf.address", val)
	}
	if cmd.Flags().Changed("upf-port") {
		val, _ := cmd.Flags().GetInt("upf-port")
		v.Set("upf.port", val)
	}
	if cmd.Flags().Changed("ue-pool") {
		val, _ := cmd.Flags().GetString("ue-pool")
		v.Set("session.ue_ip_pool", val)
	}
	if cmd.Flags().Changed("seid-start") {
		val, _ := cmd.Flags().GetUint64("seid-start")
		v.Set("session.seid_start", val)
	}
	if cmd.Flags().Changed("seid-strategy") {
		val, _ := cmd.Flags().GetString("seid-strategy")
		v.Set("session.seid_strategy", val)
	}
	if cmd.Flags().Changed("message-interval") {
		val, _ := cmd.Flags().GetInt("message-interval")
		v.Set("timing.message_interval_ms", val)
	}
	if cmd.Flags().Changed("timeout") {
		val, _ := cmd.Flags().GetInt("timeout")
		v.Set("timing.response_timeout_ms", val)
	}
	if cmd.Flags().Changed("max-retries") {
		val, _ := cmd.Flags().GetInt("max-retries")
		v.Set("timing.max_retries", val)
	}
	if cmd.Flags().Changed("log-level") {
		val, _ := cmd.Flags().GetString("log-level")
		v.Set("logging.level", val)
	}
	if cmd.Flags().Changed("cleanup") {
		val, _ := cmd.Flags().GetBool("cleanup")
		v.Set("session.cleanup_on_exit", val)
	}
	if cmd.Flags().Changed("strip-ipv6") {
		val, _ := cmd.Flags().GetBool("strip-ipv6")
		v.Set("session.strip_ipv6", val)
	}
	if cmd.Flags().Changed("repeat") {
		val, _ := cmd.Flags().GetInt("repeat")
		v.Set("input.repeat_count", val)
	}
	if cmd.Flags().Changed("repeat-interval") {
		val, _ := cmd.Flags().GetInt("repeat-interval")
		v.Set("timing.repeat_interval_ms", val)
	}
	if cmd.Flags().Changed("source-ports") {
		val, _ := cmd.Flags().GetInt("source-ports")
		v.Set("smf.source_ports", val)
	}
	if cmd.Flags().Changed("strip-vendor-ies") {
		val, _ := cmd.Flags().GetBool("strip-vendor-ies")
		v.Set("session.strip_vendor_ies", val)
	}
	if cmd.Flags().Changed("log-file") {
		val, _ := cmd.Flags().GetString("log-file")
		v.Set("logging.file", val)
	}
	// Stress test flags
	if cmd.Flags().Changed("stress") {
		val, _ := cmd.Flags().GetBool("stress")
		v.Set("stress.enabled", val)
	}
	if cmd.Flags().Changed("tps") {
		val, _ := cmd.Flags().GetInt("tps")
		v.Set("stress.tps", val)
	}
	if cmd.Flags().Changed("active-sessions") {
		val, _ := cmd.Flags().GetInt("active-sessions")
		v.Set("stress.active_sessions", val)
	}
	if cmd.Flags().Changed("duration") {
		val, _ := cmd.Flags().GetInt("duration")
		v.Set("stress.duration_sec", val)
	}
}
