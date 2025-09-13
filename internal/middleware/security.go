package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
	"golang.org/x/time/rate"
)

type SecurityConfig struct {
	AllowedOrigins    []string
	AllowedMethods    []string
	AllowedHeaders    []string
	MaxRequestsPerIP  int
	BurstLimit        int
	BlockedIPs        []string
	TrustedProxies    []string
	EnableCORS        bool
	EnableRateLimit   bool
	EnableIPFilter    bool
	MaxRequestSize    int64
	RequestTimeout    time.Duration
	EnableCSRF        bool
	CSRFSecret        string
	EnableAuth        bool
	AuthTokenHeader   string
	ValidTokens       []string
	EnableGeoBlocking bool
	BlockedCountries  []string
	EnableHoneypot    bool
	HoneypotPaths     []string
	MaxConcurrentReqs int
	EnableRequestID   bool
	EnableSecurityLog bool
}

type SecurityManager struct {
	config         *SecurityConfig
	rateLimiters   map[string]*rate.Limiter
	requestCounts  map[string]int
	blockedIPs     map[string]time.Time
	concurrentReqs int
	mu             sync.RWMutex
	csrfTokens     map[string]time.Time
	requestIDs     map[string]time.Time
	securityEvents chan SecurityEvent
}

type SecurityEvent struct {
	Type      string
	IP        string
	Path      string
	UserAgent string
	Timestamp time.Time
	Details   map[string]interface{}
}

type RequestValidator struct {
	MaxSize         int64
	AllowedTypes    []string
	BlockedPatterns []*regexp.Regexp
}

func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		AllowedOrigins:    []string{"*"},
		AllowedMethods:    []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:    []string{"*"},
		MaxRequestsPerIP:  1000,
		BurstLimit:        100,
		BlockedIPs:        []string{},
		TrustedProxies:    []string{"127.0.0.1", "::1", "192.168.0.0/16", "10.0.0.0/8"},
		EnableCORS:        true,
		EnableRateLimit:   false,
		EnableIPFilter:    false,
		MaxRequestSize:    50 * 1024 * 1024,
		RequestTimeout:    60 * time.Second,
		EnableCSRF:        false,
		CSRFSecret:        generateRandomSecret(),
		EnableAuth:        false,
		AuthTokenHeader:   "X-API-Key",
		ValidTokens:       []string{},
		EnableGeoBlocking: false,
		BlockedCountries:  []string{},
		EnableHoneypot:    false,
		HoneypotPaths:     []string{"/admin", "/wp-admin", "/.env", "/config"},
		MaxConcurrentReqs: 1000,
		EnableRequestID:   true,
		EnableSecurityLog: false,
	}
}

func NewSecurityManager(config *SecurityConfig) *SecurityManager {
	sm := &SecurityManager{
		config:         config,
		rateLimiters:   make(map[string]*rate.Limiter),
		requestCounts:  make(map[string]int),
		blockedIPs:     make(map[string]time.Time),
		csrfTokens:     make(map[string]time.Time),
		requestIDs:     make(map[string]time.Time),
		securityEvents: make(chan SecurityEvent, 1000),
	}

	if config.EnableSecurityLog {
		go sm.processSecurityEvents()
	}

	go sm.cleanupExpiredData()

	return sm
}

func (sm *SecurityManager) SecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		clientIP := sm.getClientIP(c)
		requestID := sm.generateRequestID()

		if sm.config.EnableRequestID {
			c.Header("X-Request-ID", requestID)
		}

		ctx, cancel := context.WithTimeout(c.Request.Context(), sm.config.RequestTimeout)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)

		if sm.config.EnableSecurityLog {
			sm.logSecurityEvent("request_start", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
				"request_id": requestID,
				"method":     c.Request.Method,
			})
		}

		if !sm.validateRequest(c, clientIP, requestID) {
			return
		}

		c.Next()

		latency := time.Since(start)
		if sm.config.EnableSecurityLog {
			sm.logSecurityEvent("request_complete", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
				"request_id": requestID,
				"status":     c.Writer.Status(),
				"latency":    latency,
			})
		}
	}
}

func (sm *SecurityManager) validateRequest(c *gin.Context, clientIP, requestID string) bool {
	if sm.isIPBlocked(clientIP) {
		sm.logSecurityEvent("blocked_ip", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
			"request_id": requestID,
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
		c.Abort()
		return false
	}

	if sm.config.EnableHoneypot && sm.isHoneypotPath(c.Request.URL.Path) {
		sm.logSecurityEvent("honeypot_triggered", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
			"request_id": requestID,
		})
		sm.blockIP(clientIP, 24*time.Hour)
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		c.Abort()
		return false
	}

	if sm.config.EnableRateLimit && !sm.checkRateLimit(clientIP) {
		sm.logSecurityEvent("rate_limit_exceeded", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
			"request_id": requestID,
		})
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Rate limit exceeded"})
		c.Abort()
		return false
	}

	if sm.config.EnableAuth && !sm.validateAuth(c) {
		sm.logSecurityEvent("auth_failed", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
			"request_id": requestID,
		})
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		c.Abort()
		return false
	}

	if sm.config.EnableCSRF && !sm.validateCSRF(c) {
		sm.logSecurityEvent("csrf_failed", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
			"request_id": requestID,
		})
		c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token invalid"})
		c.Abort()
		return false
	}

	if !sm.validateRequestSize(c) {
		sm.logSecurityEvent("request_too_large", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
			"request_id": requestID,
			"size":       c.Request.ContentLength,
		})
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "Request too large"})
		c.Abort()
		return false
	}

	return true
}

func (sm *SecurityManager) CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !sm.config.EnableCORS {
			c.Next()
			return
		}

		origin := c.Request.Header.Get("Origin")
		if sm.isOriginAllowed(origin) {
			c.Header("Access-Control-Allow-Origin", origin)
		}

		c.Header("Access-Control-Allow-Methods", strings.Join(sm.config.AllowedMethods, ", "))
		c.Header("Access-Control-Allow-Headers", strings.Join(sm.config.AllowedHeaders, ", "))
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")
		c.Header("Access-Control-Expose-Headers", "X-Request-ID")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

func (sm *SecurityManager) SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		c.Header("X-Download-Options", "noopen")
		c.Header("X-Permitted-Cross-Domain-Policies", "none")
		c.Header("Cross-Origin-Embedder-Policy", "require-corp")
		c.Header("Cross-Origin-Opener-Policy", "same-origin")
		c.Header("Cross-Origin-Resource-Policy", "same-origin")

		c.Next()
	}
}

func (sm *SecurityManager) RequestValidator() gin.HandlerFunc {
	validator := &RequestValidator{
		MaxSize:      sm.config.MaxRequestSize,
		AllowedTypes: []string{"application/json", "application/x-www-form-urlencoded", "multipart/form-data"},
		BlockedPatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(script|javascript|vbscript|onload|onerror|onclick)`),
			regexp.MustCompile(`(?i)(union|select|insert|update|delete|drop|create|alter)`),
			regexp.MustCompile(`(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)`),
		},
	}

	return func(c *gin.Context) {
		if !validator.validateRequest(c) {
			clientIP := sm.getClientIP(c)
			sm.logSecurityEvent("invalid_request", clientIP, c.Request.URL.Path, c.Request.UserAgent(), map[string]interface{}{
				"content_type": c.Request.Header.Get("Content-Type"),
				"size":         c.Request.ContentLength,
			})
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func (rv *RequestValidator) validateRequest(c *gin.Context) bool {
	if c.Request.ContentLength > rv.MaxSize {
		return false
	}

	contentType := c.Request.Header.Get("Content-Type")
	if !rv.isContentTypeAllowed(contentType) {
		return false
	}

	path := c.Request.URL.Path
	for _, pattern := range rv.BlockedPatterns {
		if pattern.MatchString(path) {
			return false
		}
	}

	return true
}

func (rv *RequestValidator) isContentTypeAllowed(contentType string) bool {
	for _, allowed := range rv.AllowedTypes {
		if strings.Contains(contentType, allowed) {
			return true
		}
	}
	return false
}

func (sm *SecurityManager) getClientIP(c *gin.Context) string {
	clientIP := c.ClientIP()

	if clientIP == "::1" {
		return "127.0.0.1"
	}

	if sm.isTrustedProxy(clientIP) {
		if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
			ips := strings.Split(forwarded, ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}
		if realIP := c.GetHeader("X-Real-IP"); realIP != "" {
			return realIP
		}
	}

	return clientIP
}

func (sm *SecurityManager) isTrustedProxy(ip string) bool {
	for _, trusted := range sm.config.TrustedProxies {
		if ip == trusted {
			return true
		}
	}
	return false
}

func (sm *SecurityManager) isIPBlocked(ip string) bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if blockTime, exists := sm.blockedIPs[ip]; exists {
		if time.Since(blockTime) < 24*time.Hour {
			return true
		}
		delete(sm.blockedIPs, ip)
	}

	for _, blocked := range sm.config.BlockedIPs {
		if ip == blocked {
			return true
		}
	}
	return false
}

func (sm *SecurityManager) blockIP(ip string, duration time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.blockedIPs[ip] = time.Now().Add(duration)
}

func (sm *SecurityManager) isHoneypotPath(path string) bool {
	for _, honeypot := range sm.config.HoneypotPaths {
		if strings.Contains(path, honeypot) {
			return true
		}
	}
	return false
}

func (sm *SecurityManager) checkRateLimit(ip string) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	limiter, exists := sm.rateLimiters[ip]
	if !exists {
		limiter = rate.NewLimiter(
			rate.Every(time.Second/time.Duration(sm.config.MaxRequestsPerIP)),
			sm.config.BurstLimit,
		)
		sm.rateLimiters[ip] = limiter
	}

	return limiter.Allow()
}

func (sm *SecurityManager) validateAuth(c *gin.Context) bool {
	token := c.GetHeader(sm.config.AuthTokenHeader)
	if token == "" {
		return false
	}

	for _, validToken := range sm.config.ValidTokens {
		if token == validToken {
			return true
		}
	}
	return false
}

func (sm *SecurityManager) validateCSRF(c *gin.Context) bool {
	if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
		return true
	}

	token := c.GetHeader("X-CSRF-Token")
	if token == "" {
		return false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if tokenTime, exists := sm.csrfTokens[token]; exists {
		if time.Since(tokenTime) < 1*time.Hour {
			return true
		}
		delete(sm.csrfTokens, token)
	}
	return false
}

func (sm *SecurityManager) validateRequestSize(c *gin.Context) bool {
	return c.Request.ContentLength <= sm.config.MaxRequestSize
}

func (sm *SecurityManager) isOriginAllowed(origin string) bool {
	if len(sm.config.AllowedOrigins) == 0 {
		return false
	}

	if sm.config.AllowedOrigins[0] == "*" {
		return true
	}

	for _, allowed := range sm.config.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

func (sm *SecurityManager) generateRequestID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (sm *SecurityManager) logSecurityEvent(eventType, ip, path, userAgent string, details map[string]interface{}) {
	event := SecurityEvent{
		Type:      eventType,
		IP:        ip,
		Path:      path,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Details:   details,
	}

	select {
	case sm.securityEvents <- event:
	default:
	}
}

func (sm *SecurityManager) processSecurityEvents() {
	for event := range sm.securityEvents {
		logger.WithFields(map[string]interface{}{
			"event_type": event.Type,
			"ip":         event.IP,
			"path":       event.Path,
			"user_agent": event.UserAgent,
			"timestamp":  event.Timestamp,
			"details":    event.Details,
		}).Warn("Security Event")

		if event.Type == "honeypot_triggered" || event.Type == "rate_limit_exceeded" {
			sm.blockIP(event.IP, 1*time.Hour)
		}
	}
}

func (sm *SecurityManager) cleanupExpiredData() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()

		for ip, blockTime := range sm.blockedIPs {
			if now.Sub(blockTime) > 24*time.Hour {
				delete(sm.blockedIPs, ip)
			}
		}

		for token, tokenTime := range sm.csrfTokens {
			if now.Sub(tokenTime) > 1*time.Hour {
				delete(sm.csrfTokens, token)
			}
		}

		for reqID, reqTime := range sm.requestIDs {
			if now.Sub(reqTime) > 1*time.Hour {
				delete(sm.requestIDs, reqID)
			}
		}

		sm.mu.Unlock()
	}
}

func (sm *SecurityManager) GenerateCSRFToken() string {
	token := sm.generateRequestID()
	sm.mu.Lock()
	sm.csrfTokens[token] = time.Now()
	sm.mu.Unlock()
	return token
}

func (sm *SecurityManager) GetSecurityStats() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return map[string]interface{}{
		"blocked_ips":     len(sm.blockedIPs),
		"rate_limiters":   len(sm.rateLimiters),
		"csrf_tokens":     len(sm.csrfTokens),
		"concurrent_reqs": sm.concurrentReqs,
	}
}

func generateRandomSecret() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func IsValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	privateBlocks := []*net.IPNet{
		{IP: net.IPv4(10, 0, 0, 0), Mask: net.CIDRMask(8, 32)},
		{IP: net.IPv4(172, 16, 0, 0), Mask: net.CIDRMask(12, 32)},
		{IP: net.IPv4(192, 168, 0, 0), Mask: net.CIDRMask(16, 32)},
		{IP: net.IPv6zero, Mask: net.CIDRMask(128, 128)},
	}

	for _, block := range privateBlocks {
		if block.Contains(parsedIP) {
			return true
		}
	}
	return false
}
