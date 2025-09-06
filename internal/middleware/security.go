package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
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
			logger.WithFields(map[string]interface{}{
				"ip":   ip,
				"path": c.Request.URL.Path,
			}).Warn("Rate limit exceeded")
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
			logger.WithFields(map[string]interface{}{
				"ip":   ip,
				"path": c.Request.URL.Path,
			}).Warn("Blocked IP access attempt")
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

		if statusCode >= 400 {
			logger.WithFields(map[string]interface{}{
				"method":     method,
				"path":       path,
				"client_ip":  clientIP,
				"status":     statusCode,
				"body_size":  bodySize,
				"raw_query":  raw,
				"user_agent": c.Request.UserAgent(),
				"latency":    latency,
			}).Error("HTTP Request Failed")
		} else {
			logger.WithFields(map[string]interface{}{
				"method":     method,
				"path":       path,
				"client_ip":  clientIP,
				"status":     statusCode,
				"body_size":  bodySize,
				"raw_query":  raw,
				"user_agent": c.Request.UserAgent(),
				"latency":    latency,
			}).Info("HTTP Request")
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
