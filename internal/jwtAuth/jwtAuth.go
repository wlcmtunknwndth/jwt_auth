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

// TimeToLive == Ttl
const (
	AccessToken  = "access"
	RefreshToken = "refresh"

	TtlAccess  = 2
	TtlRefresh = 5
)

func checkRequest(w http.ResponseWriter, r *http.Request, cookieName string) (*Info, error) {
	cookie, err := r.Cookie(cookieName)
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
		slog.Error("couldn't parse jwt: ", err)
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
	info, err := checkRequest(w, r, AccessToken)
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
	info, err := checkRequest(w, r, RefreshToken)
	if err != nil {
		return
	}

	// gives a new access token only if previous is about to die in 30 secs
	//if time.Until(info.ExpiresAt.Time) > 30*time.Second {
	//	slog.Error("token ", RefreshToken, " is about to out of clock")
	//	w.WriteHeader(http.StatusBadRequest)
	//	return
	//}

	expiresAt := time.Now().Add(TtlAccess * time.Minute)

	info.ExpiresAt = jwt.NewNumericDate(expiresAt)

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, info)

	tokenStr, err := token.SignedString([]byte(Key))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    AccessToken,
		Value:   tokenStr,
		Expires: expiresAt,
	})

	if _, err = w.Write([]byte(fmt.Sprintf("User %s has got a new access token", info.Username))); err != nil {
		slog.Error(`couldn't write a message to {info.Username}`)
	}
}

func WriteNewToken(w http.ResponseWriter, usr User, tokenName string) {
	var expireAt time.Time
	switch tokenName {
	case RefreshToken:
		expireAt = time.Now().Add(TtlRefresh * time.Minute)
	case AccessToken:
		expireAt = time.Now().Add(TtlAccess * time.Minute)
	default:
		return
	}

	inf := &Info{
		Username: usr.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expireAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, inf)

	tokenStr, err := token.SignedString([]byte(Key))
	if err != nil {
		slog.Error("error generating ", tokenName, "token: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:    tokenName,
		Value:   tokenStr,
		Expires: expireAt,
	})
}
