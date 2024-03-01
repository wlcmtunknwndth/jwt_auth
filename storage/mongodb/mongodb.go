package mongodb

import (
	"context"
	"github.com/wlcmtunknwndth/jwt_auth/internal/auth"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"log/slog"
	"os"
	"time"
)

const (
	DbName          = "db"
	UsersCollection = "users"
)

type Mongodb struct {
	client *mongo.Client
}

//type User struct {
//	Username string `bson:"username"`
//	Password string `bson:"password"`
//}

func New(uri string) (*Mongodb, context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var err error
	var db Mongodb
	db.client, err = mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		slog.Error("could not connect to storage: %s", err)
		os.Exit(1)
	}

	err = db.Ping(ctx)
	if err != nil {
		slog.Error("connection to storage is not established: %s", err)
		os.Exit(1)
	}
	return &db, ctx, cancel, err
}

func (db *Mongodb) Ping(ctx context.Context) error {
	if err := db.client.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}
	slog.Info("connection is alive")
	return nil
}

func (db *Mongodb) Close(ctx context.Context, cancelFunc context.CancelFunc) {
	defer func() {
		if err := db.client.Disconnect(ctx); err != nil {
			slog.Error("could not close connection: ", err)
			os.Exit(1)
		}
	}()
}

func (db *Mongodb) RegisterUser(ctx context.Context, user auth.User) error {
	collection := db.client.Database(DbName).Collection(UsersCollection)
	_, err := collection.InsertOne(ctx, user)
	return err
}

func (db *Mongodb) GetPass(ctx context.Context, username string) (string, error) {
	collection := db.client.Database(DbName).Collection(UsersCollection)

	filter := bson.D{{"username", username}}
	res := collection.FindOne(ctx, filter /*options.FindOne().SetProjection("password")*/)
	//if err != nil {
	//	if errors.Is(err, mongo.ErrNilDocument) {
	//		slog.Error("the password is missing")
	//		//os.Exit(1)
	//	}
	//	slog.Error("couldn't get a password: ", err)
	//	return
	//}
	var user auth.User
	if err := res.Decode(&user); err != nil {
		slog.Error("couldn't decode data: ", err)
		return "", err
	}
	return user.Password, nil
}
