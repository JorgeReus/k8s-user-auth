package main

import (
	"context"
	"encoding/json"
	"github.com/google/go-github/v32/github"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
	"io/ioutil"
	"log"
	"net/http"
)

type AuthRequestSpec struct {
	Token string `json:"token"`
}

type AuthRequest struct {
	ApiVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Spec       AuthRequestSpec `json:"spec"`
}

type AuthResponseStatus struct {
	Authenticated bool                    `json:"authenticated"`
	User          *AuthResponseStatusUser `json:"user,omitempty"`
}

type AuthResponseStatusUser struct {
	Username string   `json:"username"`
	Uid      string   `json:"uid"`
	Groups   []string `json:"groups"`
}

type AuthResponse struct {
	ApiVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Status     AuthResponseStatus `json:"status"`
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

var unauthorizedRespose = AuthResponse{
	ApiVersion: "authentication.k8s.io/v1beta1",
	Kind:       "TokenReview",
	Status: AuthResponseStatus{
		Authenticated: false,
	},
}

func authenticate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reqBody, _ := ioutil.ReadAll(r.Body)
	var authRequest AuthRequest
	err := json.Unmarshal(reqBody, &authRequest)

	if err != nil {
		json.NewEncoder(w).Encode(unauthorizedRespose)
		log.Printf("User : %v Cause: %v, ", reqBody, err)
		return
	}
	// Query github data username and groups of an org
	ctx := context.Background()
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: authRequest.Spec.Token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)
	req, _, err := client.Users.Get(context.Background(), "")

	if err != nil {
		json.NewEncoder(w).Encode(unauthorizedRespose)
		log.Printf("Cause: %v, ", err)
		return
	}

	user := *req.Login

	membership, _, err := client.Organizations.GetOrgMembership(context.Background(), "", "CoF-Academy")

	if err != nil {
		json.NewEncoder(w).Encode(unauthorizedRespose)
		log.Printf("User : %v Cause: %v, ", user, err)
		return
	}

	authRespose := AuthResponse{
		ApiVersion: authRequest.ApiVersion,
		Kind:       authRequest.Kind,
		Status: AuthResponseStatus{
			Authenticated: true,
			User: &AuthResponseStatusUser{
				Username: user,
				Uid:      user,
				Groups:   []string{*membership.Role},
			},
		},
	}
	json.NewEncoder(w).Encode(authRespose)
	log.Printf("User %v authenticated sucessfully", user)
}

func root(w http.ResponseWriter, r *http.Request) {
	log.Print("Root endpoint requested")
}

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc("/", root)
	myRouter.HandleFunc("/authenticate", authenticate).Methods("POST")
	log.Fatal(http.ListenAndServe(":3000", myRouter))
}

func main() {
	handleRequests()
}
