package auth

import (
	"context"
	"encoding/json"
	"github.com/wlcmtunknwndth/jwt_auth/internal/jwtAuth"
	"log/slog"
	"net/http"
	"time"
)

type Storage interface {
	GetPass(ctx context.Context, username string) (string, error)
	RegisterUser(ctx context.Context, user jwtAuth.User) error
}

func Register(w http.ResponseWriter, r *http.Request, ctx context.Context, db Storage) {
	var usr jwtAuth.User
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		slog.Info("couldn't process request: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err = db.RegisterUser(ctx, usr); err != nil {
		slog.Error("couldn't register new user: ", err)
	}

	jwtAuth.WriteNewToken(w, usr, jwtAuth.AccessToken)
	jwtAuth.WriteNewToken(w, usr, jwtAuth.RefreshToken)
}

func LogIn(w http.ResponseWriter, r *http.Request, ctx context.Context, db Storage) {
	var usr jwtAuth.User
	//ok := jwtAuth.Access(w, r)
	//if ok == true {
	//	slog.Info("user is already authorized")
	//	return
	//}
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pass, err := db.GetPass(ctx, usr.Username)
	if err != nil || pass != usr.Password {
		slog.Error("pass is not valid or couldn't check password:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	jwtAuth.WriteNewToken(w, usr, jwtAuth.AccessToken)
	jwtAuth.WriteNewToken(w, usr, jwtAuth.RefreshToken)
}

func LogOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    jwtAuth.AccessToken,
		Expires: time.Now(),
	})
	http.SetCookie(w, &http.Cookie{
		Name:    jwtAuth.RefreshToken,
		Expires: time.Now(),
	})
}
