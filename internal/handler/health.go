package handler

import (
	"net/http"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/pkg/redis"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

type HealthStatus struct {
	Status    string               `json:"status"`
	Timestamp time.Time            `json:"timestamp"`
	Service   string               `json:"service"`
	Version   string               `json:"version"`
	Uptime    string               `json:"uptime"`
	System    SystemInfo           `json:"system"`
	Checks    map[string]CheckInfo `json:"checks"`
}

type SystemInfo struct {
	GoVersion    string `json:"go_version"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
}

type CheckInfo struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	Latency string `json:"latency,omitempty"`
}

var startTime = time.Now()

func HealthCheck(c *gin.Context) {
	logger := utils.GetLogger()

	logger.Info("Health check requested",
		zap.String("ip", c.ClientIP()),
		zap.String("user_agent", c.Request.UserAgent()),
	)

	checks := make(map[string]CheckInfo)
	checks["redis"] = checkRedis()
	checks["memory"] = checkMemory()

	status := "healthy"
	for _, check := range checks {
		if check.Status == "unhealthy" {
			status = "unhealthy"
			break
		}
	}

	healthStatus := HealthStatus{
		Status:    status,
		Timestamp: time.Now().UTC(),
		Service:   "zeus-nwc-server",
		Version:   "1.0.0",
		Uptime:    time.Since(startTime).String(),
		System: SystemInfo{
			GoVersion:    runtime.Version(),
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
		},
		Checks: checks,
	}

	if status == "healthy" {
		c.JSON(http.StatusOK, healthStatus)
	} else {
		c.JSON(http.StatusServiceUnavailable, healthStatus)
	}
}

func checkRedis() CheckInfo {
	start := time.Now()

	check := CheckInfo{
		Status:  "healthy",
		Message: "Redis connection is working",
	}

	if err := redis.HealthCheck(); err != nil {
		check.Status = "unhealthy"
		check.Message = "Redis health check failed: " + err.Error()
	}

	latency := time.Since(start)
	check.Latency = latency.String()

	return check
}

func checkMemory() CheckInfo {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	check := CheckInfo{
		Status:  "healthy",
		Message: "Memory usage is normal",
	}

	if m.Alloc > 100*1024*1024 {
		check.Status = "warning"
		check.Message = "High memory usage detected"
	}

	return check
}
