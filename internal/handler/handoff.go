package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/services"
	"go.uber.org/zap"
)

type HandoffHandler struct {
	handoffService *services.HandoffService
	logger         *zap.Logger
}

func NewHandoffHandler(handoffService *services.HandoffService, logger *zap.Logger) *HandoffHandler {
	return &HandoffHandler{
		handoffService: handoffService,
		logger:         logger,
	}
}

func (h *HandoffHandler) HandleHandoff(c *gin.Context) {
	var req services.HandoffRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid handoff request", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request",
			"details": err.Error(),
		})
		return
	}

	response, err := h.handoffService.ProcessHandoff(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Failed to process handoff", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to process handoff request",
		})
		return
	}

	h.logger.Info("Handoff processed successfully",
		zap.String("service_pubkey", req.ServicePubkey),
		zap.Int("connections_count", len(req.Connections)),
	)

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
		h.logger.Error("Failed to disconnect device", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to disconnect device",
		})
		return
	}

	h.logger.Info("Device disconnected successfully", zap.String("user_id", userID))

	c.JSON(http.StatusOK, gin.H{
		"message": "Device disconnected successfully",
		"user_id": userID,
	})
}
