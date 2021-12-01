package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/devtron-labs/authenticator/middleware"
	"github.com/devtron-labs/authenticator/oidc"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
)

func main() {

	dexServerAddress := flag.String("dexServerAddress", "http://127.0.0.1:5556", "dex endpoint")
	url := flag.String("authenticatorUrl", "https://127.0.0.1:8000/", "public endpoint for authenticator")
	dexClientSecret := flag.String("dexClientSecret", "", "dex clinet secret")
	dexCLIClientID := flag.String("dexCLIClientID", "argo-cd", "dex clinet id")
	serveTls := flag.Bool("serveTls", true, "dex clinet id")
	flag.Parse()

	dexConfig := &oidc.DexConfig{
		DexServerAddress:           *dexServerAddress,
		Url:                        *url,
		DexClientSecret:            *dexClientSecret,
		DexClientID:                *dexCLIClientID,
		UserSessionDurationSeconds: 10000,
	}
	userVerier := func(email string) bool { return true }
	redirectUrlSanitiser := func(url string) string { return url }
	oidcClient, dexProxy, err := oidc.GetOidcClient(dexConfig, userVerier, redirectUrlSanitiser)
	if err != nil {
		fmt.Println(err)
		return
	}
	settings, err := oidc.GetSettings(dexConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	sessionManager := middleware.NewSessionManager(settings, dexConfig.DexServerAddress)
	loginService := middleware.NewUserLogin(sessionManager)
	// dex setting ends
	r := mux.NewRouter().StrictSlash(false)
	r.PathPrefix("/api/dex").HandlerFunc(dexProxy)
	r.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, "Hello, user!\n")
	})
	r.HandleFunc("/auth/login", oidcClient.HandleLogin)
	r.HandleFunc("/auth/callback", oidcClient.HandleCallback)
	helloHandler := func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	}
	r.HandleFunc("/user/login", func(writer http.ResponseWriter, request *http.Request) {
		up := &userNamePassword{}
		decoder := json.NewDecoder(request.Body)
		err := decoder.Decode(up)
		if err != nil {
			fmt.Println(err)
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		token, err := loginService.CreateLoginSession(up.Username, up.Password)
		if err != nil {
			fmt.Println(err)
			http.Error(writer, fmt.Errorf("invalid username or password").Error(), http.StatusForbidden)
			return
		}
		response := make(map[string]interface{})
		response["token"] = token
		http.SetCookie(writer, &http.Cookie{Name: "argocd.token", Value: token, Path: "/"})
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		b, err := json.Marshal(response)
		if err != nil {
			fmt.Println(err)
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Write(b)
		return
	}).Methods("POST")
	r.HandleFunc("/hello", helloHandler)
	log.Println("Listing for requests at http://localhost:8000/hello")
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", 8000),
		Handler: middleware.Authorizer(sessionManager, middleware.WhitelistChecker)(r),
	}
	if *serveTls {
		cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
		if err != nil {
			log.Fatal(err)
		}
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		server.ListenAndServeTLS("", "")
	} else {
		server.ListenAndServe()
	}
	if err != nil {
		log.Fatal(err)
	}
}

type userNamePassword struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required,min=6"`
}
