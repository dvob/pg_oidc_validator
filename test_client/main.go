package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2/clientcredentials"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	var (
		clientID     string
		clientSecret string
		issuerURL    string
		tokenFile    string
		connString   string
	)

	flag.StringVar(&tokenFile, "token-file", "", "Path to file containing the access token")
	flag.StringVar(&clientID, "client-id", clientID, "OAuth Client ID")
	flag.StringVar(&clientSecret, "client-secret", clientSecret, "OAuth Client Secret")
	flag.StringVar(&issuerURL, "issuer-url", issuerURL, "OIDC Issuer URL")
	flag.StringVar(&connString, "conn", connString, "Connectino string. e.g.: host=localhost port=5432 dbname=postgres user=postgres sslmode=disable")

	err := readFlagsFromEnv(flag.CommandLine, "")
	if err != nil {
		return fmt.Errorf("failed to read config from environment: %w", err)
	}
	flag.Parse()

	var (
		oauthTokenProvider func(ctx context.Context) (string, error)
		ctx                = context.Background()
	)
	if tokenFile != "" {
		log.Printf("Configure OAuth2 Token Provider with access token from file %s", tokenFile)
		oauthTokenProvider = func(ctx context.Context) (string, error) {
			log.Printf("Reading access token from file %s", tokenFile)
			data, err := os.ReadFile(tokenFile)
			if err != nil {
				return "", fmt.Errorf("failed to read access token from file: %w", err)
			}
			return string(data), nil
		}
	} else {
		if clientID == "" || clientSecret == "" || issuerURL == "" {
			return fmt.Errorf("either --file or all of --client-id, --client-secret, and --issuer must be provided")
		}
		log.Printf("Performing OIDC discovery %s", issuerURL)
		provider, err := oidc.NewProvider(ctx, issuerURL)
		if err != nil {
			return fmt.Errorf("failed to discover OIDC provider: %w", err)
		}

		oauthConfig := clientcredentials.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			TokenURL:     provider.Endpoint().TokenURL,
		}

		log.Printf("Configure OAuth2 Token Provider with client credentials flow client_id=%s", clientID)
		oauthTokenProvider = func(ctx context.Context) (string, error) {
			log.Printf("Perform client credentials flow to get access token")
			token, err := oauthConfig.Token(ctx)
			if err != nil {
				return "", fmt.Errorf("failed to get access token: %w", err)
			}
			return token.AccessToken, nil
		}

	}

	config, err := pgx.ParseConfig(connString)
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}
	config.OAuthTokenProvider = oauthTokenProvider

	log.Printf("connect to database")
	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close(ctx)

	log.Println("Connected successfully!")

	var result string
	err = conn.QueryRow(ctx, "SELECT current_user").Scan(&result)
	if err != nil {
		return fmt.Errorf("failed to query: %w", err)
	}

	log.Printf("Current user: %s\n", result)
	return nil
}

// readFlagsFromEnv reads configuration values from environment. This function
// can be called before flag.Parse() to read settings from the environment but
// allow to override settings by using flags.
func readFlagsFromEnv(fs *flag.FlagSet, prefix string) error {
	errs := []error{}
	fs.VisitAll(func(f *flag.Flag) {
		envVarName := prefix + f.Name
		envVarName = strings.ReplaceAll(envVarName, "-", "_")
		envVarName = strings.ToUpper(envVarName)
		val, ok := os.LookupEnv(envVarName)
		if !ok {
			return
		}
		err := f.Value.Set(val)
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid value '%s' in %s: %w", val, envVarName, err))
		}
	})
	return errors.Join(errs...)
}
