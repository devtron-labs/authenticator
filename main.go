package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	client2 "github.com/devtron-labs/authenticator/client"
	"github.com/devtron-labs/authenticator/middleware"
	"github.com/gorilla/mux"
	"io"
	"log"
	"net/http"
)

func main() {

	h := sha256.New()
	_, err := h.Write([]byte("RLVvy5OgjuJrgQi0GcuvfvC8s/FGdP2zluXSahYxUdM="))
	if err != nil {
		panic(err)
	}
	sha := h.Sum(nil)
	s := base64.URLEncoding.EncodeToString(sha)[:40]

	fmt.Println(s)
	dexServerAddress := flag.String("dexServerAddress", "http://127.0.0.1:5556", "dex endpoint")
	dexCLIClientID := flag.String("dexCLIClientID", "argo-cd", "dex clinet id")
	serveTls := flag.Bool("serveTls", true, "dex clinet id")
	flag.Parse()

	client, err := client2.NewK8sClient(true)
	if err != nil {
		panic(err)
	}
	dexConfig, err := client.GetServerSettings()
	if err != nil {
		panic(err)
	}
	dexConfig.DexServerAddress = *dexServerAddress
	dexConfig.DexClientID = *dexCLIClientID
	dexConfig.UserSessionDurationSeconds = 10000

	userVerier := func(email string) bool { return true }
	redirectUrlSanitiser := func(url string) string { return url }
	oidcClient, dexProxy, err := client2.GetOidcClient(dexConfig, userVerier, redirectUrlSanitiser)
	if err != nil {
		fmt.Println(err)
		return
	}
	settings, err := client2.GetSettings(dexConfig)
	if err != nil {
		fmt.Println(err)
		return
	}
	sessionManager := middleware.NewSessionManager(settings, dexConfig)
	loginService := middleware.NewUserLogin(sessionManager, client)

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
