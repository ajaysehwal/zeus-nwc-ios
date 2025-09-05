package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/internal/handler"
	"github.com/zeusln/ios-nwc-server/internal/middleware"
	"github.com/zeusln/ios-nwc-server/pkg/utils"
	"go.uber.org/zap"
)

type Server struct {
	router *gin.Engine
	server *http.Server
	logger *utils.Logger
}

func NewServer(cfg *config.Config) *Server {
	router := gin.New()
	router.Use(gin.Recovery())

	return &Server{
		router: router,
		logger: utils.GetLogger(),
	}
}

func (s *Server) SetupRoutes(securityConfig *middleware.SecurityConfig, handlerManager *handler.HandlerManager, logger *zap.Logger) {
	SetupRoutes(s.router, securityConfig, handlerManager, logger)
}

func (s *Server) Start(addr string) error {
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	s.logger.Info("Starting server", zap.String("address", addr))
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		s.logger.Info("Shutting down server")
		return s.server.Shutdown(ctx)
	}
	return nil
}
