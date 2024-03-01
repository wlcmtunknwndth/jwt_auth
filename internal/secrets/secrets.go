package secrets

import (
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"
	"log/slog"
	"os"
	"time"
)

type Config struct {
	Key         string     `yaml:"secret_key" env-required:"true"`   //`json:"secret_key"`
	StoragePath string     `yaml:"storage_path" env-required:"true"` //`json:"storage_path"`
	DBHost      string     `yaml:"db_host" env-required:"true"`      //`json:"db_host"`
	Server      HTTPServer `yaml:"http_server"`                      //`json:"http_server"`
}

type HTTPServer struct { //`json:"port:"`
	Timeout     time.Duration `yaml:"timeout" env-default:"5s"`             //`json:"Timeout"`
	IdleTimeout time.Duration `yaml:"idle_timeout" env-default:"60s"`       //`json:"IdleTimeout"`
	Address     string        `yaml:"address" env-default:"localhost:8080"` //`json:"Address"`
}

func MustLoad() *Config {
	if err := godotenv.Load("local.env"); err != nil {
		slog.Error("no .env file found: ", err)
		os.Exit(1)
	}
	slog.Info(".env file found")

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		slog.Error("no config path set")
		os.Exit(1)
	}
	slog.Info(configPath)
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		slog.Error("config file does not exist: %s", configPath)
		os.Exit(1)
	}

	//byteFile, err := os.ReadFile(configPath)
	//if err != nil {
	//	slog.Error("config file does not exists: ", err, configPath)
	//	os.Exit(1)
	//}

	var cfg Config
	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		slog.Error("couldn't read config: ", err)
		os.Exit(1)
	}
	//err = json.Unmarshal(byteFile, &cfg)
	//if err != nil {
	//	slog.Error("failed to unmarshall config: ", err)
	//	os.Exit(1)
	//}
	return &cfg
}
