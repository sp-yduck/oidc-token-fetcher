/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

var callbackChan = make(chan error)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "oidc-token-fetcher",
	Short: "fetch oidc token from issuer in semi-automated way",
	Long:  ``,
	RunE: func(cmd *cobra.Command, args []string) error {
		bindAddress := cmd.Flag("bind-address").Value.String()
		bindPort := ":" + cmd.Flag("bind-port").Value.String()
		redirectPath := cmd.Flag("callback-path").Value.String()
		redirectURL := "http://" + bindAddress + bindPort + redirectPath
		clientID := cmd.Flag("client-id").Value.String()
		clientSecret := cmd.Flag("client-secret").Value.String()

		if clientID == "" || clientSecret == "" {
			return fmt.Errorf("client-id and client-secret are required")
		}

		ctx := context.Background()
		provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
		if err != nil {
			return err
		}
		oidcConfig := &oidc.Config{
			ClientID: clientID,
		}
		verifier := provider.Verifier(oidcConfig)

		config := oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}

		state, err := randString(16)
		if err != nil {
			return err
		}
		nonce, err := randString(16)
		if err != nil {
			return err
		}

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			setCallbackCookie(w, r, "state", state)
			setCallbackCookie(w, r, "nonce", nonce)
			http.Redirect(w, r, config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
		})

		// if err := browser.OpenURL(config.AuthCodeURL(state, oidc.Nonce(nonce))); err != nil {
		// 	return err
		// }

		http.HandleFunc(redirectPath, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("state") != state {
				http.Error(w, "state did not match", http.StatusBadRequest)
				callbackChan <- err
				return
			}

			oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
			if err != nil {
				http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
				callbackChan <- err
				return
			}
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
				callbackChan <- fmt.Errorf("No id_token field in oauth2 token.")
				return
			}
			idToken, err := verifier.Verify(ctx, rawIDToken)
			if err != nil {
				http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
				callbackChan <- err
				return
			}

			if idToken.Nonce != nonce {
				http.Error(w, "nonce did not match", http.StatusBadRequest)
				callbackChan <- fmt.Errorf("nonce did not match")
				return
			}

			// oauth2Token.AccessToken = "*REDACTED*"
			resp := struct {
				OAuth2Token   *oauth2.Token
				IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
			}{oauth2Token, new(json.RawMessage)}

			if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				callbackChan <- err
				return
			}
			data, err := json.MarshalIndent(resp, "", "    ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				callbackChan <- err
				return
			}
			w.Write(data)
			callbackChan <- nil
		})

		log.Printf("listening on http://%s/", bindAddress+bindPort)
		go http.ListenAndServe(bindAddress+bindPort, nil)
		select {
		case err := <-callbackChan:
			return err
		case <-time.After(time.Second * 60):
			return fmt.Errorf("timeout")
		}
	},
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func setCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("bind-address", "a", "127.0.0.1", "bind address")
	rootCmd.Flags().IntP("bind-port", "P", 5556, "bind port")
	rootCmd.Flags().StringP("callback-path", "p", "/auth/oauth2/callback", "callback url path")
	rootCmd.Flags().StringP("issuer-url", "i", "https://accounts.google.com", "oidc issuer endpoint url")
	rootCmd.Flags().StringP("client-id", "c", "", "client id for oidc")
	rootCmd.Flags().StringP("client-secret", "s", "", "client secret for oidc")
}
