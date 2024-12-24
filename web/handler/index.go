package handler

import (
	"easyrsa-web-ui/app/easyrsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/text/language"
)

func createBundle() (*i18n.Bundle, error) {
	bundle := i18n.NewBundle(language.English)
	bundle.RegisterUnmarshalFunc("toml", toml.Unmarshal)
	err := filepath.WalkDir("web/res/i18n", func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Ext(info.Name()) != ".toml" {
			return nil
		}
		_, err = bundle.LoadMessageFile(path)
		return err
	})
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func Index(w http.ResponseWriter, r *http.Request) {
	bundle, err := createBundle()
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	lang := r.Header.Get("Accept-Language")
	localizer := i18n.NewLocalizer(bundle, lang)
	t := template.Must(template.New("index.html").Funcs(template.FuncMap{
		"toDate": func(t2 time.Time) string {
			if t2.IsZero() {
				return "-"
			}
			w := t2.Local()
			year, month, day := w.Date()
			return fmt.Sprintf("%d/%02d/%02d", year, month, day)
		},
		"t": func(text string) string {
			str, err := localizer.Localize(&i18n.LocalizeConfig{MessageID: text})
			if err != nil {
				return fmt.Sprintf("[TL err: %s]", err.Error())
			}
			return str
		},
	}).ParseFiles("web/template/index.html"))
	err = t.Execute(w, map[string]interface{}{})
	if err != nil {
		fmt.Fprintln(w, err)
	}
}

func List(w http.ResponseWriter, r *http.Request) {
	l, err := easyrsa.Clients()
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	err = json.NewEncoder(w).Encode(l)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
}

func Create(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name != "" {
		err := easyrsa.CreateClient(name)
		if err != nil {
			fmt.Fprintln(w, err)
			return
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
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Unrevoke(w http.ResponseWriter, r *http.Request) {
	serial := chi.URLParam(r, "serial")
	err := easyrsa.UnrevokeClient(serial)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func Renew(w http.ResponseWriter, r *http.Request) {
	identity := chi.URLParam(r, "identity")
	err := easyrsa.RenewClient(identity)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
