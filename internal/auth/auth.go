package auth

import (
	"context"
	"encoding/json"
	"github.com/golang-jwt/jwt/v5"
	"log/slog"
	"net/http"
	"os"
	"time"
)

var Key, _ = os.LookupEnv("secret_key")

type User struct {
	Username string `bson:"username" json:"username"`
	Password string `bson:"password" json:"password"`
}

type Info struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Storage interface {
	GetPass(ctx context.Context, username string) (string, error)
	RegisterUser(ctx context.Context, user User) error
}

func Register(w http.ResponseWriter, r *http.Request, ctx context.Context, db Storage) {
	var usr User
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		slog.Info("couldn't process request: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if err = db.RegisterUser(ctx, usr); err != nil {
		slog.Error("couldn't register new user: ", err)
	}

	//expireAt := time.Now().Add(10 * time.Minute)
	//inf := &Info{
	//	Username: usr.Username,
	//	RegisteredClaims: jwt.RegisteredClaims{
	//		ExpiresAt: jwt.NewNumericDate(expireAt),
	//	},
	//}
	//
	//token := jwt.NewWithClaims(jwt.SigningMethodHS512, inf)
	//
	//tokenStr, err := token.SignedString([]byte(Key))
	//if err != nil {
	//	w.WriteHeader(http.StatusInternalServerError)
	//	return
	//}
	//
	//http.SetCookie(w, &http.Cookie{
	//	Name:    "token",
	//	Value:   tokenStr,
	//	Expires: expireAt,
	//})
}

func LogIn(w http.ResponseWriter, r *http.Request, ctx context.Context, db Storage) {
	var usr User
	err := json.NewDecoder(r.Body).Decode(&usr)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	pass, err := db.GetPass(ctx, usr.Username)
	if err != nil || pass != usr.Password {
		slog.Error("couldn't check password:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	expireAt := time.Now().Add(10 * time.Minute)

	inf := &Info{
		Username: usr.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, inf)

	//key, ok := os.LookupEnv("secret_key")
	//if !ok {
	//	slog.Error("missing secret key")
	//	return
	//}
	tokenStr, err := token.SignedString([]byte(Key))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenStr,
		Expires: expireAt,
	})
}

func LogOut(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Expires: time.Now(),
	})
}
