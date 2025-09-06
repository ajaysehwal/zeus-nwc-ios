package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/services"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

type HandoffHandler struct {
	handoffService *services.HandoffService
}

func NewHandoffHandler(handoffService *services.HandoffService) *HandoffHandler {
	return &HandoffHandler{
		handoffService: handoffService,
	}
}

func (h *HandoffHandler) HandleHandoff(c *gin.Context) {
	var req services.HandoffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		logger.WithError(err).Error("Invalid handoff request")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	response, err := h.handoffService.ProcessHandoff(c.Request.Context(), &req)
	if err != nil {
		logger.WithError(err).Error("Failed to process handoff")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process handoff request",
		})
		return
	}

	logger.WithFields(map[string]interface{}{
		"service_pubkey":    req.ServicePubkey,
		"connections_count": len(req.Connections),
	}).Info("Handoff processed successfully")

	c.JSON(http.StatusOK, response)
}

func (h *HandoffHandler) HandleDisconnect(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "User ID is required",
		})
		return
	}

	err := h.handoffService.DisconnectDevice(c.Request.Context(), userID)
	if err != nil {
		logger.WithError(err).Error("Failed to disconnect device")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to disconnect device",
		})
		return
	}

	logger.WithField("user_id", userID).Info("Device disconnected successfully")

	c.JSON(http.StatusOK, gin.H{
		"message": "Device disconnected successfully",
		"user_id": userID,
	})
}
