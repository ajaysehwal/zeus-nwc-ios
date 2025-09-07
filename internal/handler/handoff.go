package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/services"
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
	var req services.Handoff
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if err := h.handoffService.HandleHandoff(c.Request.Context(), &req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "handoff processed"})
}

func (h *HandoffHandler) HandleRestore(c *gin.Context) {
	deviceToken := c.Query("device_token")
	handoff, events, err := h.handoffService.HandleRestore(c.Request.Context(), deviceToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"connections": handoff.Connections, "events": events})
}