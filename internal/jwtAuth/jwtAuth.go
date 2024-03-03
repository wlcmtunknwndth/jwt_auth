package jwtAuth

import (
	"errors"
	"fmt"
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

func checkRequest(w http.ResponseWriter, r *http.Request) (*Info, error) {
	cookie, err := r.Cookie("token")
	if err != nil {
		slog.Error("error looking for cookies: ", err)
		if errors.Is(err, http.ErrNoCookie) {
			w.WriteHeader(http.StatusUnauthorized)
			return nil, err
		}
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("no cookies found: %s", err)
	}

	tokenStr := cookie.Value

	var info Info

	token, err := jwt.ParseWithClaims(tokenStr, &info, func(token *jwt.Token) (any, error) {
		return []byte(Key), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			w.WriteHeader(http.StatusUnauthorized)
			return nil, err
		}
		w.WriteHeader(http.StatusBadRequest)
		return nil, fmt.Errorf("auth error: %s", err)
	}

	if !token.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return nil, fmt.Errorf("the token is invalid")
	}
	return &info, nil
}

func Access(w http.ResponseWriter, r *http.Request) bool {
	info, err := checkRequest(w, r)
	if err != nil {
		slog.Error("wasn't able to find token: ", err)
		return false
	}
	if _, err = w.Write([]byte(fmt.Sprintf("User %s authorized", info.Username))); err != nil {
		slog.Info("couldn't reply to user ", info.Username)
		return false
	}
	return true
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

	expiresAt := time.Now().Add(5 * time.Minute)

	info.ExpiresAt = jwt.NewNumericDate(expiresAt)

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, info)

	tokenStr, err := token.SignedString([]byte(Key))
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

//func WriteNewToken(w http.ResponseWriter, usr User, tokenName string){
//	expireAt := time.Now().Add(1 * time.Minute)
//
//	inf := &Info{
//		Username: usr.Username,
//		RegisteredClaims: jwt.RegisteredClaims{
//			ExpiresAt: jwt.NewNumericDate(expireAt),
//		},
//	}
//
//	token := jwt.NewWithClaims(jwt.SigningMethodHS512, inf)
//
//	//key, ok := os.LookupEnv("secret_key")
//	//if !ok {
//	//	slog.Error("missing secret key")
//	//	return
//	//}
//	tokenStr, err := token.SignedString([]byte(Key))
//	if err != nil {
//		w.WriteHeader(http.StatusInternalServerError)
//		return
//	}
//
//	http.SetCookie(w, &http.Cookie{
//		Name:    tokenName,
//		Value:   tokenStr,
//		Expires: expireAt,
//}
