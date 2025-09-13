package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server        ServerConfig       `json:"server"`
	Redis         RedisConfig        `json:"redis"`
	Security      SecurityConfig     `json:"security"`
	Log           LogConfig          `json:"log"`
	Notifications NotificationConfig `json:"notifications"`
}

type ServerConfig struct {
	Port         string        `json:"port"`
	Host         string        `json:"host"`
	ReadTimeout  time.Duration `json:"read_timeout"`
	WriteTimeout time.Duration `json:"write_timeout"`
	IdleTimeout  time.Duration `json:"idle_timeout"`
}

type RedisConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Password string `json:"password"`
	DB       int    `json:"db"`
	PoolSize int    `json:"pool_size"`
}

type SecurityConfig struct {
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	MaxRequestsPerIP int      `json:"max_requests_per_ip"`
	BurstLimit       int      `json:"burst_limit"`
	BlockedIPs       []string `json:"blocked_ips"`
	TrustedProxies   []string `json:"trusted_proxies"`
	EnableCORS       bool     `json:"enable_cors"`
	EnableRateLimit  bool     `json:"enable_rate_limit"`
	EnableIPFilter   bool     `json:"enable_ip_filter"`
}

type LogConfig struct {
	Level       string `json:"level"`
	Environment string `json:"environment"`
	ServiceName string `json:"service_name"`
	OutputPath  string `json:"output_path"`
	PrettyPrint bool   `json:"pretty_print"`
	Colorful    bool   `json:"colorful"`
}

type NotificationConfig struct {
	APNS APNSConfig `json:"apns"`
}

type APNSConfig struct {
	KeyID      string `json:"key_id"`
	TeamID     string `json:"team_id"`
	BundleID   string `json:"bundle_id"`
	KeyPath    string `json:"key_path"`
	Production bool   `json:"production"`
	Enabled    bool   `json:"enabled"`
}

func Load() *Config {
	env := getEnv("ENV", "development")

	return &Config{
		Server:        loadServerConfig(env),
		Redis:         loadRedisConfig(env),
		Security:      loadSecurityConfig(env),
		Log:           loadLogConfig(env),
		Notifications: loadNotificationConfig(env),
	}
}

func loadServerConfig(env string) ServerConfig {
	port := getEnv("PORT", "8080")
	host := getEnv("HOST", "0.0.0.0")

	readTimeout := getDurationEnv("READ_TIMEOUT", 15*time.Second)
	writeTimeout := getDurationEnv("WRITE_TIMEOUT", 15*time.Second)
	idleTimeout := getDurationEnv("IDLE_TIMEOUT", 60*time.Second)

	if env == "production" {
		readTimeout = 30 * time.Second
		writeTimeout = 30 * time.Second
		idleTimeout = 120 * time.Second
	}

	return ServerConfig{
		Port:         port,
		Host:         host,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
}

func loadRedisConfig(env string) RedisConfig {
	host := getEnv("REDIS_HOST", "localhost")
	port := getIntEnv("REDIS_PORT", 6379)
	password := getEnv("REDIS_PASSWORD", "admin")
	db := getIntEnv("REDIS_DB", 0)
	poolSize := getIntEnv("REDIS_POOL_SIZE", 10)

	if env == "production" {
		poolSize = 20
	}

	return RedisConfig{
		Host:     host,
		Port:     port,
		Password: password,
		DB:       db,
		PoolSize: poolSize,
	}
}

func loadSecurityConfig(env string) SecurityConfig {
	allowedMethods := getStringSliceEnv("ALLOWED_METHODS", []string{"GET", "POST"})
	maxRequestsPerIP := getIntEnv("MAX_REQUESTS_PER_IP", 1000)
	burstLimit := getIntEnv("BURST_LIMIT", 100)
	blockedIPs := getStringSliceEnv("BLOCKED_IPS", []string{})
	trustedProxies := getStringSliceEnv("TRUSTED_PROXIES", []string{"127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8"})

	var allowedOrigins, allowedHeaders []string

	if env == "production" {
		allowedOrigins = getStringSliceEnv("ALLOWED_ORIGINS", []string{"https://yourdomain.com"})
		allowedHeaders = getStringSliceEnv("ALLOWED_HEADERS", []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With"})
		maxRequestsPerIP = 200
		burstLimit = 50
	} else {
		allowedOrigins = []string{"*"}
		allowedHeaders = []string{"*"}
	}

	return SecurityConfig{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   allowedMethods,
		AllowedHeaders:   allowedHeaders,
		MaxRequestsPerIP: maxRequestsPerIP,
		BurstLimit:       burstLimit,
		BlockedIPs:       blockedIPs,
		TrustedProxies:   trustedProxies,
		EnableCORS:       getBoolEnv("ENABLE_CORS", true),
		EnableRateLimit:  getBoolEnv("ENABLE_RATE_LIMIT", env == "production"),
		EnableIPFilter:   getBoolEnv("ENABLE_IP_FILTER", env == "production"),
	}
}

func loadLogConfig(env string) LogConfig {
	level := getEnv("LOG_LEVEL", "info")
	serviceName := getEnv("SERVICE_NAME", "zeus-nwc-server")
	outputPath := getEnv("LOG_OUTPUT_PATH", "")
	prettyPrint := getBoolEnv("LOG_PRETTY_PRINT", env == "development")
	colorful := getBoolEnv("LOG_COLORFUL", env == "development")

	return LogConfig{
		Level:       level,
		Environment: env,
		ServiceName: serviceName,
		OutputPath:  outputPath,
		PrettyPrint: prettyPrint,
		Colorful:    colorful,
	}
}

func (c *Config) ToMiddlewareSecurityConfig() *SecurityConfig {
	return &c.Security
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

func getStringSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return []string{value}
	}
	return defaultValue
}

func loadNotificationConfig(env string) NotificationConfig {
	return NotificationConfig{
		APNS: loadAPNSConfig(env),
	}
}

func loadAPNSConfig(env string) APNSConfig {
	keyID := getEnv("APNS_KEY_ID", "")
	teamID := getEnv("APNS_TEAM_ID", "")
	bundleID := getEnv("APNS_BUNDLE_ID", "com.zeusln.ios-nwc-server")
	keyPath := getEnv("APNS_KEY_PATH", "")
	production := getBoolEnv("APNS_PRODUCTION", env == "production")
	enabled := getBoolEnv("APNS_ENABLED", true)

	return APNSConfig{
		KeyID:      keyID,
		TeamID:     teamID,
		BundleID:   bundleID,
		KeyPath:    keyPath,
		Production: production,
		Enabled:    enabled,
	}
}
