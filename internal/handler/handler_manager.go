package handler

import (
	"github.com/zeusln/ios-nwc-server/internal/services"
)

type HandlerManager struct {
	handoffService *services.EventsService
}

func NewHandlerManager(serviceManager *services.ServiceManager) *HandlerManager {
	return &HandlerManager{
		handoffService: serviceManager.GetEventsService(),
	}
}
func (hm *HandlerManager) GetHandoffService() *services.EventsService {
	return hm.handoffService
}
