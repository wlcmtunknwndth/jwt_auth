package main

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/wlcmtunknwndth/jwt_auth/internal/auth"
	"github.com/wlcmtunknwndth/jwt_auth/internal/jwtAuth"
	"github.com/wlcmtunknwndth/jwt_auth/internal/secrets"
	"github.com/wlcmtunknwndth/jwt_auth/storage/mongodb"
	"log/slog"
	"net/http"
	"os"
)

var config *secrets.Config

func init() {
	config = secrets.MustLoad()
}

func main() {
	db, ctx, cancel, err := mongodb.New(config.DBHost)
	if err != nil {
		slog.Error("Error while connecting to db: ", err)
		os.Exit(1)
	}
	defer db.Close(ctx, cancel)

	router := chi.NewRouter()

	router.Use(middleware.RequestID)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Logger)
	router.Use(middleware.URLFormat)

	router.Post("/logout", func(w http.ResponseWriter, r *http.Request) {
		auth.LogOut(w, r)
	})
	router.Post("/access", func(w http.ResponseWriter, r *http.Request) {
		jwtAuth.Access(w, r)
	})

	router.Post("/refresh", func(w http.ResponseWriter, r *http.Request) {
		jwtAuth.Refresh(w, r)
	})
	router.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		auth.LogIn(w, r, context.TODO(), db)
	})

	router.Post("/register", func(w http.ResponseWriter, r *http.Request) {
		auth.Register(w, r, context.TODO(), db)
	})

	srv := &http.Server{
		Addr:         config.Server.Address,
		Handler:      router,
		ReadTimeout:  config.Server.Timeout,
		WriteTimeout: config.Server.Timeout,
		IdleTimeout:  config.Server.IdleTimeout,
	}

	if err := srv.ListenAndServe(); err != nil {
		slog.Error("failed to start server")
	}
	slog.Error("server stopped")
}
