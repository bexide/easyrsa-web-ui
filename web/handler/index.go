package handler

import (
	"easyrsa-web-ui/app/config"
	"easyrsa-web-ui/app/easyrsa"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

func Index(w http.ResponseWriter, r *http.Request) {
	l, err := easyrsa.Clients()
	if err != nil {
		fmt.Fprintln(w, err)
	}
	t := template.Must(template.New("web/template/index.html").Funcs(template.FuncMap{
		"toDate": func(t2 time.Time) string {
			if t2.IsZero() {
				return "-"
			}
			w := t2.Local()
			year, month, day := w.Date()
			return fmt.Sprintf("%d/%02d/%02d", year, month, day)
		},
	}).ParseFiles("web/template/index.html"))
	if err != nil {
		fmt.Fprintln(w, err)
	}
	err = t.Execute(w, map[string]interface{}{
		"Clients": l,
		"Config":  config.Current,
	})
	if err != nil {
		fmt.Fprintln(w, err)
	}
}

func Create(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name != "" {
		err := easyrsa.CreateClient(name)
		if err != nil {
			fmt.Fprintln(w, err)
		}
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func GetP12(w http.ResponseWriter, r *http.Request) {
	identity := chi.URLParam(r, "identity")
	out, err := easyrsa.GetP12(identity)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	w.Header().Add("Content-Type", "application/x-pkcs12")
	w.Header().Add("Content-DIsposition", fmt.Sprintf("attachment; filename=\"%s.p12\"", identity))
	w.Write(out)
}

func GetOvpn(w http.ResponseWriter, r *http.Request) {
	identity := chi.URLParam(r, "identity")
	out, err := easyrsa.GetOvpn(identity)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	w.Header().Add("Content-Type", "application/x-openvpn-profile")
	w.Header().Add("Content-DIsposition", fmt.Sprintf("attachment; filename=\"%s.ovpn\"", identity))
	w.Write(out)
}

func Revoke(w http.ResponseWriter, r *http.Request) {
	identity := chi.URLParam(r, "identity")
	err := easyrsa.RevokeClient(identity)
	if err != nil {
		fmt.Fprintln(w, err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Unrevoke(w http.ResponseWriter, r *http.Request) {
	identity := chi.URLParam(r, "identity")
	err := easyrsa.UnrevokeClient(identity)
	if err != nil {
		fmt.Fprintln(w, err)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
