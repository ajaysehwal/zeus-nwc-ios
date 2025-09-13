package handler

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/services"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

type EventsHandlers struct {
	handoffService *services.EventsService
}

type HandoffRequest struct {
	DeviceToken string       `json:"device_token" binding:"required,min=1,max=255"`
	Connections []Connection `json:"connections" binding:"required"`
}

type Connection struct {
	RelayURL string `json:"relay" binding:"required"`
	PubKey   string `json:"pubkey" binding:"required"`
}

type RestoreResponse struct {
	Connections []Connection `json:"connections"`
	Events      []string     `json:"events"`
}

var (
	deviceTokenRegex = regexp.MustCompile(`^[a-zA-Z0-9\-_]{1,255}$`)
)

func NewEventsHandlers(handoffService *services.EventsService) *EventsHandlers {
	return &EventsHandlers{
		handoffService: handoffService,
	}
}

func (h *EventsHandlers) HandleHandoff(c *gin.Context) {
	var req HandoffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WithFields(map[string]interface{}{
			"error": err.Error(),
			"ip":    c.ClientIP(),
		}).Warn("Invalid handoff request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request format"})
		return
	}

	if !h.validateHandoffRequest(&req) {
		logger.WithFields(map[string]interface{}{
			"ip":           c.ClientIP(),
			"device_token": req.DeviceToken,
		}).Warn("Invalid handoff request data")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
		return
	}

	handoff := &services.Handoff{
		DeviceToken: req.DeviceToken,
		Connections: convertToServiceConnections(req.Connections),
	}

	if err := h.handoffService.HandleHandoff(c.Request.Context(), handoff); err != nil {
		logger.WithFields(map[string]interface{}{
			"error":        err.Error(),
			"ip":           c.ClientIP(),
			"device_token": req.DeviceToken,
		}).Error("Handoff processing failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Processing failed"})
		return
	}

	logger.WithFields(map[string]interface{}{
		"ip":           c.ClientIP(),
		"device_token": req.DeviceToken,
	}).Info("Handoff processed successfully")

	c.JSON(http.StatusOK, gin.H{"message": "Handoff processed successfully"})
}

func (h *EventsHandlers) HandleRestore(c *gin.Context) {
	deviceToken := strings.TrimSpace(c.Query("device_token"))

	if !h.validateDeviceToken(deviceToken) {
		logger.WithFields(map[string]interface{}{
			"ip":           c.ClientIP(),
			"device_token": deviceToken,
		}).Warn("Invalid device token in restore request")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device token"})
		return
	}

	handoff, events, err := h.handoffService.HandleRestore(c.Request.Context(), deviceToken)
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"error":        err.Error(),
			"ip":           c.ClientIP(),
			"device_token": deviceToken,
		}).Error("Restore processing failed")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Restore failed"})
		return
	}

	response := RestoreResponse{
		Connections: convertFromServiceConnections(handoff.Connections),
		Events:      events,
	}

	logger.WithFields(map[string]interface{}{
		"ip":           c.ClientIP(),
		"device_token": deviceToken,
	}).Info("Restore processed successfully")

	c.JSON(http.StatusOK, response)
}

func (h *EventsHandlers) validateHandoffRequest(req *HandoffRequest) bool {
	if !h.validateDeviceToken(req.DeviceToken) {
		return false
	}

	if len(req.Connections) == 0 {
		return false
	}

	if len(req.Connections) > 100 {
		return false
	}

	return true
}

func (h *EventsHandlers) validateDeviceToken(token string) bool {
	if token == "" {
		return false
	}

	if len(token) > 255 {
		return false
	}

	return deviceTokenRegex.MatchString(token)
}

func convertToServiceConnections(connections []Connection) []services.Connection {
	serviceConnections := make([]services.Connection, len(connections))
	for i, conn := range connections {
		serviceConnections[i] = services.Connection{
			RelayURL: conn.RelayURL,
			PubKey:   conn.PubKey,
		}
	}
	return serviceConnections
}

func convertFromServiceConnections(connections []services.Connection) []Connection {
	handlerConnections := make([]Connection, len(connections))
	for i, conn := range connections {
		handlerConnections[i] = Connection{
			RelayURL: conn.RelayURL,
			PubKey:   conn.PubKey,
		}
	}
	return handlerConnections
}
