package web

import (
	"easyrsa-web-ui/app/config"
	"easyrsa-web-ui/web/handler"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func Init() {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)
	r.Use(middleware.CleanPath)

	r.HandleFunc("/", handler.Index)
	r.Post("/user/create", handler.Create)
	r.Get("/user/{identity}/p12", handler.GetP12)
	r.Get("/user/{identity}/ovpn", handler.GetOvpn)
	r.Post("/user/{identity}/revoke", handler.Revoke)
	r.Post("/user/{identity}/unrevoke", handler.Unrevoke)
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static"))))
	port := os.Getenv("PORT")
	if port == "" {
		port = config.Current.ListenPort
	}
	http.ListenAndServe(config.Current.ListenHost+":"+port, r)
}
