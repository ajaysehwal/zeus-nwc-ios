package services

import (
	"context"
)

type HandoffService struct {
	nostrService *NostrService
}

func NewHandoffService(nostrService *NostrService) *HandoffService {
	return &HandoffService{
		nostrService: nostrService,
	}
}

func (s *HandoffService) HandleHandoff(ctx context.Context, req *Handoff) error {
	return s.nostrService.ProcessHandoff(ctx, req)
}

func (s *HandoffService) HandleRestore(ctx context.Context, deviceToken string) (Handoff, []string, error) {
	return s.nostrService.HandleRestore(ctx, deviceToken)
}