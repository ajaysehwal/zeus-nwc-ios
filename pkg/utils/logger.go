package utils

import (
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
}

type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
	FatalLevel LogLevel = "fatal"
)

type Config struct {
	Level       LogLevel
	Environment string
	ServiceName string
	OutputPath  string
	PrettyPrint bool
	Colorful    bool
}

func DefaultConfig() *Config {
	return &Config{
		Level:       InfoLevel,
		Environment: getEnv("ENV", "development"),
		ServiceName: getEnv("SERVICE_NAME", "zeus-nwc-server"),
		OutputPath:  "",
		PrettyPrint: getEnv("ENV", "development") == "development",
		Colorful:    getEnv("ENV", "development") == "development",
	}
}

func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	level, err := zapcore.ParseLevel(string(config.Level))
	if err != nil {
		level = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	encoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder

	var encoder zapcore.Encoder
	if config.PrettyPrint {
		if config.Colorful {
			encoder = newColorfulConsoleEncoder(encoderConfig)
		} else {
			encoder = zapcore.NewConsoleEncoder(encoderConfig)
		}
	} else {
		encoder = zapcore.NewJSONEncoder(encoderConfig)
	}

	var core zapcore.Core
	if config.OutputPath != "" {
		file, err := os.OpenFile(config.OutputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		core = zapcore.NewCore(encoder, zapcore.AddSync(file), level)
	} else {
		core = zapcore.NewCore(encoder, zapcore.AddSync(os.Stdout), level)
	}

	logger := zap.New(core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.Fields(
			zap.String("service", config.ServiceName),
			zap.String("environment", config.Environment),
		),
	)

	return &Logger{Logger: logger}, nil
}

type colorfulConsoleEncoder struct {
	zapcore.Encoder
}

func newColorfulConsoleEncoder(encoderConfig zapcore.EncoderConfig) zapcore.Encoder {
	return &colorfulConsoleEncoder{
		Encoder: zapcore.NewConsoleEncoder(encoderConfig),
	}
}

func (c *colorfulConsoleEncoder) EncodeEntry(entry zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	level := entry.Level
	var emoji, color, levelColor string

	switch level {
	case zapcore.DebugLevel:
		emoji = "🔍"
		color = "\033[36m"      // Cyan
		levelColor = "\033[96m" // Bright Cyan
	case zapcore.InfoLevel:
		emoji = "ℹ️ "
		color = "\033[32m"      // Green
		levelColor = "\033[92m" // Bright Green
	case zapcore.WarnLevel:
		emoji = "⚠️ "
		color = "\033[33m"      // Yellow
		levelColor = "\033[93m" // Bright Yellow
	case zapcore.ErrorLevel:
		emoji = "❌"
		color = "\033[31m"      // Red
		levelColor = "\033[91m" // Bright Red
	case zapcore.FatalLevel:
		emoji = "💀"
		color = "\033[35m"      // Magenta
		levelColor = "\033[95m" // Bright Magenta
	default:
		emoji = "📝"
		color = "\033[37m"      // White
		levelColor = "\033[97m" // Bright White
	}

	resetColor := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"

	// Format timestamp
	timestamp := entry.Time.Format("15:04:05")
	formattedTime := dim + "[" + timestamp + "]" + resetColor

	// Format level
	levelName := level.String()
	formattedLevel := levelColor + bold + "[" + levelName + "]" + resetColor

	// Format message with emoji
	coloredMessage := color + emoji + " " + entry.Message + resetColor

	// Format caller if available
	var callerInfo string
	if entry.Caller.Defined {
		callerInfo = dim + " (" + entry.Caller.TrimmedPath() + ")" + resetColor
	}

	// Create the final formatted message
	finalMessage := formattedTime + " " + formattedLevel + " " + coloredMessage + callerInfo

	coloredEntry := zapcore.Entry{
		Level:      entry.Level,
		Time:       entry.Time,
		LoggerName: entry.LoggerName,
		Message:    finalMessage,
		Caller:     entry.Caller,
		Stack:      entry.Stack,
	}

	return c.Encoder.EncodeEntry(coloredEntry, fields)
}

func MustNewLogger(config *Config) *Logger {
	logger, err := NewLogger(config)
	if err != nil {
		panic(err)
	}
	return logger
}

func (l *Logger) Info(msg string, fields ...zap.Field) {
	l.Logger.Info(msg, fields...)
}

func (l *Logger) Infof(format string, args ...interface{}) {
	l.Logger.Sugar().Infof(format, args...)
}

func (l *Logger) Debug(msg string, fields ...zap.Field) {
	l.Logger.Debug(msg, fields...)
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.Logger.Sugar().Debugf(format, args...)
}

func (l *Logger) Warn(msg string, fields ...zap.Field) {
	l.Logger.Warn(msg, fields...)
}

func (l *Logger) Warnf(format string, args ...interface{}) {
	l.Logger.Sugar().Warnf(format, args...)
}

func (l *Logger) Error(msg string, fields ...zap.Field) {
	l.Logger.Error(msg, fields...)
}

func (l *Logger) Errorf(format string, args ...interface{}) {
	l.Logger.Sugar().Errorf(format, args...)
}

func (l *Logger) Fatal(msg string, fields ...zap.Field) {
	l.Logger.Fatal(msg, fields...)
}

func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.Logger.Sugar().Fatalf(format, args...)
}

func (l *Logger) Success(msg string, fields ...zap.Field) {
	successMsg := "✅ " + msg
	l.Logger.Info(successMsg, fields...)
}

func (l *Logger) Successf(format string, args ...interface{}) {
	successMsg := "✅ " + format
	l.Logger.Sugar().Infof(successMsg, args...)
}

func (l *Logger) Critical(msg string, fields ...zap.Field) {
	criticalMsg := "🚨 " + msg
	l.Logger.Error(criticalMsg, fields...)
}

func (l *Logger) Criticalf(format string, args ...interface{}) {
	criticalMsg := "🚨 " + format
	l.Logger.Sugar().Errorf(criticalMsg, args...)
}

// Specialized logging methods for different operations
func (l *Logger) HTTPRequest(method, path, remoteAddr string, status int, duration time.Duration, fields ...zap.Field) {
	emoji := "🌐"
	if status >= 400 {
		emoji = "❌"
	} else if status >= 300 {
		emoji = "🔄"
	}

	allFields := []zap.Field{
		zap.String("http_method", method),
		zap.String("http_path", path),
		zap.String("remote_addr", remoteAddr),
		zap.Int("status", status),
		zap.Duration("duration", duration),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info(emoji+" HTTP Request", allFields...)
}

func (l *Logger) DatabaseOperation(operation, table string, duration time.Duration, fields ...zap.Field) {
	allFields := []zap.Field{
		zap.String("operation", operation),
		zap.String("table", table),
		zap.Duration("duration", duration),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info("🗄️ Database Operation", allFields...)
}

func (l *Logger) RedisOperation(operation, key string, duration time.Duration, fields ...zap.Field) {
	allFields := []zap.Field{
		zap.String("operation", operation),
		zap.String("key", key),
		zap.Duration("duration", duration),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info("🔴 Redis Operation", allFields...)
}

func (l *Logger) NostrEvent(eventType, eventID, pubkey string, fields ...zap.Field) {
	allFields := []zap.Field{
		zap.String("event_type", eventType),
		zap.String("event_id", eventID),
		zap.String("pubkey", pubkey),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info("⚡ Nostr Event", allFields...)
}

func (l *Logger) RelayConnection(relayURL, status string, fields ...zap.Field) {
	emoji := "🔌"
	if status == "connected" {
		emoji = "✅"
	} else if status == "failed" {
		emoji = "❌"
	} else if status == "retrying" {
		emoji = "🔄"
	}

	allFields := []zap.Field{
		zap.String("relay_url", relayURL),
		zap.String("status", status),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info(emoji+" Relay Connection", allFields...)
}

func (l *Logger) NotificationSent(deviceToken, title string, success bool, fields ...zap.Field) {
	emoji := "📱"
	if success {
		emoji = "✅"
	} else {
		emoji = "❌"
	}

	allFields := []zap.Field{
		zap.String("device_token", deviceToken[:8]+"..."), // Truncate for privacy
		zap.String("title", title),
		zap.Bool("success", success),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info(emoji+" Notification", allFields...)
}

func (l *Logger) ServiceStart(serviceName, version string, fields ...zap.Field) {
	allFields := []zap.Field{
		zap.String("service", serviceName),
		zap.String("version", version),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info("🚀 Service Started", allFields...)
}

func (l *Logger) ServiceStop(serviceName string, fields ...zap.Field) {
	allFields := []zap.Field{
		zap.String("service", serviceName),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info("🛑 Service Stopped", allFields...)
}

func (l *Logger) ConfigurationLoad(configType string, fields ...zap.Field) {
	allFields := []zap.Field{
		zap.String("config_type", configType),
	}
	allFields = append(allFields, fields...)

	l.Logger.Info("⚙️ Configuration Loaded", allFields...)
}

func (l *Logger) SecurityEvent(eventType, severity string, fields ...zap.Field) {
	emoji := "🔒"
	if severity == "high" {
		emoji = "🚨"
	} else if severity == "medium" {
		emoji = "⚠️"
	}

	allFields := []zap.Field{
		zap.String("event_type", eventType),
		zap.String("severity", severity),
	}
	allFields = append(allFields, fields...)

	l.Logger.Warn(emoji+" Security Event", allFields...)
}

func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{Logger: l.Logger.With(zap.String("request_id", requestID))}
}

func (l *Logger) WithUser(userID string, username string) *Logger {
	return &Logger{Logger: l.Logger.With(
		zap.String("user_id", userID),
		zap.String("username", username),
	)}
}

func (l *Logger) WithHTTPRequest(method, path, remoteAddr string) *Logger {
	return &Logger{Logger: l.Logger.With(
		zap.String("http_method", method),
		zap.String("http_path", path),
		zap.String("remote_addr", remoteAddr),
	)}
}

func (l *Logger) WithDuration(duration time.Duration) *Logger {
	return &Logger{Logger: l.Logger.With(zap.Duration("duration", duration))}
}

func (l *Logger) WithError(err error) *Logger {
	return &Logger{Logger: l.Logger.With(zap.Error(err))}
}

func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{Logger: l.Logger.With(zap.String("component", component))}
}

func (l *Logger) WithOperation(operation string) *Logger {
	return &Logger{Logger: l.Logger.With(zap.String("operation", operation))}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

var globalLogger *Logger

func InitGlobalLogger(config *Config) error {
	logger, err := NewLogger(config)
	if err != nil {
		return err
	}
	globalLogger = logger
	return nil
}

func GetLogger() *Logger {
	if globalLogger == nil {
		globalLogger = MustNewLogger(DefaultConfig())
	}
	return globalLogger
}

func Info(msg string, fields ...zap.Field) {
	GetLogger().Info(msg, fields...)
}

func Infof(format string, args ...interface{}) {
	GetLogger().Infof(format, args...)
}

func Debug(msg string, fields ...zap.Field) {
	GetLogger().Debug(msg, fields...)
}

func Debugf(format string, args ...interface{}) {
	GetLogger().Debugf(format, args...)
}

func Warn(msg string, fields ...zap.Field) {
	GetLogger().Warn(msg, fields...)
}

func Warnf(format string, args ...interface{}) {
	GetLogger().Warnf(format, args...)
}

func Error(msg string, fields ...zap.Field) {
	GetLogger().Error(msg, fields...)
}

func Errorf(format string, args ...interface{}) {
	GetLogger().Errorf(format, args...)
}

func Fatal(msg string, fields ...zap.Field) {
	GetLogger().Fatal(msg, fields...)
}

func Fatalf(format string, args ...interface{}) {
	GetLogger().Fatalf(format, args...)
}

func Success(msg string, fields ...zap.Field) {
	GetLogger().Success(msg, fields...)
}

func Successf(format string, args ...interface{}) {
	GetLogger().Successf(format, args...)
}

func Critical(msg string, fields ...zap.Field) {
	GetLogger().Critical(msg, fields...)
}

func Criticalf(format string, args ...interface{}) {
	GetLogger().Criticalf(format, args...)
}

// Global convenience functions for specialized logging
func HTTPRequest(method, path, remoteAddr string, status int, duration time.Duration, fields ...zap.Field) {
	GetLogger().HTTPRequest(method, path, remoteAddr, status, duration, fields...)
}

func DatabaseOperation(operation, table string, duration time.Duration, fields ...zap.Field) {
	GetLogger().DatabaseOperation(operation, table, duration, fields...)
}

func RedisOperation(operation, key string, duration time.Duration, fields ...zap.Field) {
	GetLogger().RedisOperation(operation, key, duration, fields...)
}

func NostrEvent(eventType, eventID, pubkey string, fields ...zap.Field) {
	GetLogger().NostrEvent(eventType, eventID, pubkey, fields...)
}

func RelayConnection(relayURL, status string, fields ...zap.Field) {
	GetLogger().RelayConnection(relayURL, status, fields...)
}

func NotificationSent(deviceToken, title string, success bool, fields ...zap.Field) {
	GetLogger().NotificationSent(deviceToken, title, success, fields...)
}

func ServiceStart(serviceName, version string, fields ...zap.Field) {
	GetLogger().ServiceStart(serviceName, version, fields...)
}

func ServiceStop(serviceName string, fields ...zap.Field) {
	GetLogger().ServiceStop(serviceName, fields...)
}

func ConfigurationLoad(configType string, fields ...zap.Field) {
	GetLogger().ConfigurationLoad(configType, fields...)
}

func SecurityEvent(eventType, severity string, fields ...zap.Field) {
	GetLogger().SecurityEvent(eventType, severity, fields...)
}
