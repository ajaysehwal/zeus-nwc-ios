package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type SecurityConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	MaxRequestsPerIP int
	BurstLimit       int
	BlockedIPs       []string
	TrustedProxies   []string
	EnableCORS       bool
	EnableRateLimit  bool
	EnableIPFilter   bool
}

func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Accept", "Authorization"},
		MaxRequestsPerIP: 100,
		BurstLimit:       20,
		BlockedIPs:       []string{},
		TrustedProxies:   []string{"127.0.0.1", "::1"},
		EnableCORS:       true,
		EnableRateLimit:  true,
		EnableIPFilter:   true,
	}
}

type RateLimiter struct {
	limiters map[string]*rate.Limiter
	config   *SecurityConfig
}

func NewRateLimiter(config *SecurityConfig) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

func (rl *RateLimiter) getLimiter(ip string) *rate.Limiter {
	if limiter, exists := rl.limiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Every(time.Second/time.Duration(rl.config.MaxRequestsPerIP)), rl.config.BurstLimit)
	rl.limiters[ip] = limiter
	return limiter
}

func (rl *RateLimiter) RateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := getClientIP(c)

		if !rl.getLimiter(ip).Allow() {
			logger := utils.GetLogger()
			logger.Warn("Rate limit exceeded",
				zap.String("ip", ip),
				zap.String("path", c.Request.URL.Path),
			)
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func CORS(config *SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		if config.EnableCORS && isOriginAllowed(origin, config.AllowedOrigins) {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowedHeaders, ", "))
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func IPFilter(config *SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !config.EnableIPFilter {
			c.Next()
			return
		}

		ip := getClientIP(c)

		if isIPBlocked(ip, config.BlockedIPs) {
			logger := utils.GetLogger()
			logger.Warn("Blocked IP access attempt",
				zap.String("ip", ip),
				zap.String("path", c.Request.URL.Path),
			)
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		c.Next()
	}
}

func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		clientIP := getClientIP(c)
		method := c.Request.Method
		statusCode := c.Writer.Status()
		bodySize := c.Writer.Size()

		logger := utils.GetLogger()
		reqLogger := logger.WithHTTPRequest(method, path, clientIP)

		if statusCode >= 400 {
			reqLogger.WithDuration(latency).Error("HTTP Request Failed",
				zap.Int("status", statusCode),
				zap.Int("body_size", bodySize),
				zap.String("raw_query", raw),
				zap.String("user_agent", c.Request.UserAgent()),
			)
		} else {
			reqLogger.WithDuration(latency).Info("HTTP Request",
				zap.Int("status", statusCode),
				zap.Int("body_size", bodySize),
				zap.String("raw_query", raw),
				zap.String("user_agent", c.Request.UserAgent()),
			)
		}
	}
}

func getClientIP(c *gin.Context) string {
	clientIP := c.ClientIP()

	if clientIP == "::1" {
		return "127.0.0.1"
	}

	return clientIP
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	if len(allowedOrigins) == 0 {
		return false
	}

	if allowedOrigins[0] == "*" {
		return true
	}

	for _, allowed := range allowedOrigins {
		if origin == allowed {
			return true
		}
	}

	return false
}

func isIPBlocked(ip string, blockedIPs []string) bool {
	for _, blocked := range blockedIPs {
		if ip == blocked {
			return true
		}
	}
	return false
}
