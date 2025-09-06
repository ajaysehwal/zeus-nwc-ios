package logger

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

type Logger struct {
	*logrus.Logger
	config Config
}

type Config struct {
	Level       string `yaml:"level" json:"level"`
	Environment string `yaml:"environment" json:"environment"`
	Service     string `yaml:"service" json:"service"`
	Version     string `yaml:"version" json:"version"`
	File        string `yaml:"file" json:"file"`
	MaxSize     int    `yaml:"max_size" json:"max_size"`
	MaxBackups  int    `yaml:"max_backups" json:"max_backups"`
	MaxAge      int    `yaml:"max_age" json:"max_age"`
	Compress    bool   `yaml:"compress" json:"compress"`
}

type devFormatter struct{}

func (f *devFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var b strings.Builder
	
	timestamp := entry.Time.Format("15:04:05")
	b.WriteString(color.HiBlackString(timestamp))
	b.WriteString(" ")
	
	level := strings.ToUpper(entry.Level.String())
	switch entry.Level {
	case logrus.DebugLevel:
		b.WriteString(color.CyanString("%-5s", level))
	case logrus.InfoLevel:
		b.WriteString(color.GreenString("%-5s", level))
	case logrus.WarnLevel:
		b.WriteString(color.YellowString("%-5s", level))
	case logrus.ErrorLevel:
		b.WriteString(color.RedString("%-5s", level))
	case logrus.FatalLevel:
		b.WriteString(color.New(color.BgRed, color.FgWhite).Sprintf("%-5s", level))
	default:
		b.WriteString(fmt.Sprintf("%-5s", level))
	}
	b.WriteString(" ")
	
	if entry.HasCaller() {
		caller := fmt.Sprintf("%s:%d", filepath.Base(entry.Caller.File), entry.Caller.Line)
		b.WriteString(color.HiBlackString("(%s) ", caller))
	}
	
	b.WriteString(entry.Message)
	
	if len(entry.Data) > 0 {
		b.WriteString(" ")
		for k, v := range entry.Data {
			b.WriteString(color.HiBlueString("%s", k))
			b.WriteString(fmt.Sprintf("=%v ", v))
		}
	}
	
	b.WriteString("\n")
	return []byte(b.String()), nil
}

var defaultLogger *Logger

func New(cfg Config) (*Logger, error) {
	setDefaults(&cfg)
	
	logger := logrus.New()
	
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %s", cfg.Level)
	}
	logger.SetLevel(level)
	
	if cfg.Environment == "production" {
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyTime:  "timestamp",
				logrus.FieldKeyLevel: "level",
				logrus.FieldKeyMsg:   "message",
			},
		})
	} else {
		logger.SetFormatter(&devFormatter{})
		logger.SetReportCaller(true)
	}
	
	if cfg.File != "" {
		if err := setupFileOutput(logger, cfg); err != nil {
			return nil, err
		}
	}
	
	l := &Logger{
		Logger: logger,
		config: cfg,
	}
	
	l.WithFields(logrus.Fields{
		"service":     cfg.Service,
		"version":     cfg.Version,
		"environment": cfg.Environment,
		"level":       level.String(),
	}).Info("Logger initialized")
	
	return l, nil
}

func Init(cfg Config) error {
	logger, err := New(cfg)
	if err != nil {
		return err
	}
	defaultLogger = logger
	return nil
}

func setDefaults(cfg *Config) {
	if cfg.Level == "" {
		cfg.Level = "info"
	}
	if cfg.Environment == "" {
		cfg.Environment = "development"
	}
	if cfg.MaxSize == 0 {
		cfg.MaxSize = 100
	}
	if cfg.MaxBackups == 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 30
	}
}

func setupFileOutput(logger *logrus.Logger, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.File), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	
	rotateLogger := &lumberjack.Logger{
		Filename:   cfg.File,
		MaxSize:    cfg.MaxSize,
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,
		Compress:   cfg.Compress,
	}
	
	if cfg.Environment == "production" {
		logger.SetOutput(rotateLogger)
	} else {
		logger.SetOutput(io.MultiWriter(os.Stdout, rotateLogger))
	}
	
	return nil
}

type Entry struct {
	*logrus.Entry
}

func (e *Entry) With(key string, value interface{}) *Entry {
	return &Entry{e.Entry.WithField(key, value)}
}

func (e *Entry) WithFields(fields map[string]interface{}) *Entry {
	return &Entry{e.Entry.WithFields(fields)}
}

func (e *Entry) WithError(err error) *Entry {
	return &Entry{e.Entry.WithError(err)}
}

func (e *Entry) WithContext(ctx context.Context) *Entry {
	fields := extractContextFields(ctx)
	if len(fields) == 0 {
		return e
	}
	return &Entry{e.Entry.WithFields(fields)}
}

func extractContextFields(ctx context.Context) logrus.Fields {
	fields := logrus.Fields{}
	
	contextKeys := []string{
		"request_id", "user_id", "correlation_id", "trace_id", "span_id",
		"operation", "component", "session_id",
	}
	
	for _, key := range contextKeys {
		if value := ctx.Value(key); value != nil {
			fields[key] = value
		}
	}
	
	return fields
}

func WithField(key string, value interface{}) *Entry {
	return &Entry{defaultLogger.WithField(key, value)}
}

func WithFields(fields map[string]interface{}) *Entry {
	return &Entry{defaultLogger.WithFields(fields)}
}

func WithError(err error) *Entry {
	return &Entry{defaultLogger.WithError(err)}
}

func WithContext(ctx context.Context) *Entry {
	fields := extractContextFields(ctx)
	return &Entry{defaultLogger.WithFields(fields)}
}

func WithRequest(requestID string) *Entry {
	return WithField("request_id", requestID)
}

func WithUser(userID string) *Entry {
	return WithField("user_id", userID)
}

func WithTrace(traceID, spanID string) *Entry {
	return WithFields(map[string]interface{}{
		"trace_id": traceID,
		"span_id":  spanID,
	})
}

func WithOperation(operation string) *Entry {
	return WithField("operation", operation)
}

func WithComponent(component string) *Entry {
	return WithField("component", component)
}

func WithDuration(d time.Duration) *Entry {
	return WithField("duration_ms", float64(d.Nanoseconds())/1e6)
}

func Debug(msg string) {
	defaultLogger.Debug(msg)
}

func Debugf(format string, args ...interface{}) {
	defaultLogger.Debugf(format, args...)
}

func Info(msg string) {
	defaultLogger.Info(msg)
}

func Infof(format string, args ...interface{}) {
	defaultLogger.Infof(format, args...)
}

func Warn(msg string) {
	defaultLogger.Warn(msg)
}

func Warnf(format string, args ...interface{}) {
	defaultLogger.Warnf(format, args...)
}

func Error(msg string) {
	defaultLogger.Error(msg)
}

func Errorf(format string, args ...interface{}) {
	defaultLogger.Errorf(format, args...)
}

func Fatal(msg string) {
	defaultLogger.Fatal(msg)
}

func Fatalf(format string, args ...interface{}) {
	defaultLogger.Fatalf(format, args...)
}

func Panic(msg string) {
	defaultLogger.Panic(msg)
}

func Panicf(format string, args ...interface{}) {
	defaultLogger.Panicf(format, args...)
}

func GetLevel() logrus.Level {
	return defaultLogger.GetLevel()
}

func SetLevel(level logrus.Level) {
	defaultLogger.SetLevel(level)
}