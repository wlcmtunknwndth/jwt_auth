package jwtAuth

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wlcmtunknwndth/jwt_auth/internal/auth"
	"log/slog"
	"net/http"
	"time"
)

func checkRequest(w http.ResponseWriter, r *http.Request) (*auth.Info, error) {
	cookie, err := r.Cookie("token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			w.WriteHeader(http.StatusUnauthorized)
			return nil, err
		}
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("no cookies found: %s", err)
	}

	tokenStr := cookie.Value

	var info auth.Info

	token, err := jwt.ParseWithClaims(tokenStr, info, func(token *jwt.Token) (any, error) {
		return []byte(auth.Key), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			w.WriteHeader(http.StatusUnauthorized)
			return nil, err
		}
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("auth auth error: %s", err)
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, fmt.Errorf("the token is invalid")
	}
	return &info, nil
}

func Access(w http.ResponseWriter, r *http.Request) {
	info, err := checkRequest(w, r)
	if err != nil {
		slog.Error("wasn't able to find token: ", err)
	}
	if _, err = w.Write([]byte(fmt.Sprintf("User %s authorized", info.Username))); err != nil {
		slog.Info("couldn't reply to user ", info.Username)
	}
}

func Refresh(w http.ResponseWriter, r *http.Request) {
	info, err := checkRequest(w, r)
	if err != nil {
		return
	}

	if time.Until(info.ExpiresAt.Time) > 30*time.Second {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expiresAt := time.Now().Add(10 * time.Minute)

	info.ExpiresAt = jwt.NewNumericDate(expiresAt)

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, info)

	tokenStr, err := token.SignedString([]byte(auth.Key))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expiresAt,
	})
}
