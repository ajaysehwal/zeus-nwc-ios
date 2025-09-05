package handler

import (
	"github.com/zeusln/ios-nwc-server/internal/services"
)

type HandlerManager struct {
	handoffService *services.HandoffService
}

func NewHandlerManager(serviceManager *services.ServiceManager) *HandlerManager {
	return &HandlerManager{
		handoffService: serviceManager.GetHandoffService(),
	}
}

func (hm *HandlerManager) GetHandoffService() *services.HandoffService {
	return hm.handoffService
}
