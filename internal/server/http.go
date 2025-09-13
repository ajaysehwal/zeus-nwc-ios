package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/zeusln/ios-nwc-server/internal/config"
	"github.com/zeusln/ios-nwc-server/internal/handler"
	"github.com/zeusln/ios-nwc-server/internal/middleware"
	"github.com/zeusln/ios-nwc-server/pkg/logger"
)

type Server struct {
	router *gin.Engine
	server *http.Server
}

func NewServer(cfg *config.Config) *Server {
	router := gin.New()
	router.Use(gin.Recovery())

	return &Server{
		router: router,
	}
}

func (s *Server) SetupRoutes(securityManager *middleware.SecurityManager, handlerManager *handler.HandlerManager) {
	SetupRoutes(s.router, securityManager, handlerManager)
}

func (s *Server) Start(addr string) error {
	s.server = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	logger.WithField("address", addr).Info("Starting server")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.server != nil {
		logger.Info("Shutting down server")
		return s.server.Shutdown(ctx)
	}
	return nil
}
