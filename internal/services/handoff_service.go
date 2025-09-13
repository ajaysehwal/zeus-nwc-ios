package services

import (
	"context"
)

type EventsService struct {
	nostrService *NostrService
}

func NewEventsService(nostrService *NostrService) *EventsService {
	return &EventsService{
		nostrService: nostrService,
	}
}

func (s *EventsService) HandleHandoff(ctx context.Context, req *Handoff) error {
	return s.nostrService.ProcessHandoff(ctx, req)
}

func (s *EventsService) HandleRestore(ctx context.Context, deviceToken string) (Handoff, []string, error) {
	return s.nostrService.HandleRestore(ctx, deviceToken)
}