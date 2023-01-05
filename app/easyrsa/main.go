package easyrsa

import (
	"bufio"
	"easyrsa-web-ui/app/config"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type EasyrsaClient struct {
	Identity   string
	Status     string
	ExpireDate time.Time
	RevokeDate time.Time
}

type indexData struct {
	Flag          string
	ExpireDate    string
	RevoceDate    string
	SerialNumber  string
	Filename      string
	Distinguished string
}

const (
	dateFormat = "060102150405Z"
)

func init() {
}

func pkiPath() string {
	return filepath.Join(config.Current.Path, "pki")
}
func pkiIndexPath() string {
	return filepath.Join(pkiPath(), "index.txt")
}

func IsInitialized() bool {
	_, err := os.Stat(config.Current.EasyrsaConfig.Path)
	return err == nil
}

func Initialize() error {
	os.Mkdir(config.Current.Path, 0755)
	err := execCmd(fmt.Sprintf("cd %s && curl -sL https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz | tar -xzv --strip-components=1 -C .", config.Current.Path))
	if err != nil {
		return err
	}
	err = execCmd(fmt.Sprintf("cd %s && ./easyrsa init-pki", config.Current.Path))
	if err != nil {
		return err
	}
	err = execCmd(fmt.Sprintf("cd %s && echo \"ca\" | ./easyrsa build-ca nopass", config.Current.Path))
	if err != nil {
		return err
	}
	err = execCmd(fmt.Sprintf("cd %s && ./easyrsa build-server-full server nopass", config.Current.Path))
	if err != nil {
		return err
	}

	if config.Current.OpenvpnConfig.Support {
		err = execCmd(fmt.Sprintf("cd %s && ./easyrsa gen-dh", config.Current.Path))
		if err != nil {
			return err
		}
		err = execCmd(fmt.Sprintf("cd %s && cd pki && openvpn --genkey --secret ta.key", config.Current.Path))
		if err != nil {
			return err
		}
	}
	return nil
}

func execCmd(command string) error {
	cmd := exec.Command("bash", "-c", command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	logrus.Debug(out)
	return nil
}

func parseDate(src string) time.Time {
	if src == "" {
		return time.Time{}
	}
	t, err := time.Parse(dateFormat, src)
	if err != nil {
		return time.Time{}
	}
	return t
}

func parseIndex() ([]indexData, error) {
	ret := []indexData{}

	f, err := os.Open(pkiIndexPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b := bufio.NewReader(f)
	r := csv.NewReader(b)
	r.Comma = '\t'
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	for _, v := range records {
		ret = append(ret, indexData{
			Flag:          v[0],
			ExpireDate:    v[1],
			RevoceDate:    v[2],
			SerialNumber:  v[3],
			Filename:      v[4],
			Distinguished: v[5],
		})
	}
	return ret, nil
}

func getKey(name string) (string, error) {
	ret, err := os.ReadFile(filepath.Join(pkiPath(), "private", name+".key"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func getCrt(name string) (string, error) {
	ret, err := os.ReadFile(filepath.Join(pkiPath(), "issued", name+".crt"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func ServerCa() (string, error) {
	ret, err := os.ReadFile(filepath.Join(pkiPath(), "ca.crt"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func ServerTa() (string, error) {
	ret, err := os.ReadFile(filepath.Join(pkiPath(), "ta.key"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func Clients() ([]EasyrsaClient, error) {
	ret := []EasyrsaClient{}

	l, err := parseIndex()
	if err != nil {
		return nil, err
	}
	for _, v := range l {
		item := EasyrsaClient{
			Identity:   v.Distinguished[strings.Index(v.Distinguished, "=")+1:],
			ExpireDate: parseDate(v.ExpireDate),
			RevokeDate: parseDate(v.RevoceDate),
		}
		if item.Identity == "server" {
			continue
		}
		switch v.Flag {
		case "V":
			item.Status = "Active"
		case "R":
			item.Status = "Revoked"
		case "E":
			item.Status = "Expired"
		}
		ret = append(ret, item)
	}
	return ret, nil
}

func CreateClient(name string) error {
	reg := regexp.MustCompile(`^([a-zA-Z0-9_.-@])+$`)
	if !reg.MatchString(name) {
		return errors.New("username can only contains [a-zA-Z0-9_.-@]")
	}
	return execCmd(fmt.Sprintf("cd %s && ./easyrsa build-client-full %s nopass", config.Current.Path, name))
}

func RevokeClient(name string) error {
	reg := regexp.MustCompile(`^([a-zA-Z0-9_.-@])+$`)
	if !reg.MatchString(name) {
		return errors.New("username can only contains [a-zA-Z0-9_.-@]")
	}
	return execCmd(fmt.Sprintf("cd %s && echo yes | ./easyrsa revoke %s && ./easyrsa gen-crl", config.Current.Path, name))
}

func GetProfile(name string) ([]byte, error) {
	if !config.Current.OpenvpnConfig.Support {
		return nil, errors.New("openvpn not support")
	}
	key, err := getKey(name)
	if err != nil {
		return nil, err
	}
	crt, err := getCrt(name)
	if err != nil {
		return nil, err
	}
	ca, err := ServerCa()
	if err != nil {
		return nil, err
	}
	ta, err := ServerTa()
	if err != nil {
		ta = ""
		// return nil, err
	}
	ret := fmt.Sprintf(`client
dev tun
proto udp
remote %s %s
resolv-retry infinite
nobind
persist-key
persist-tun
verb 3
keepalive 10 1200
inactive 3600
key-direction 1
remote-cert-tls server
compress lz4-v2
<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>`, config.Current.ServerName, config.Current.ServerPort, ca, crt, key)
	if ta != "" {
		ret = fmt.Sprintf(`%s
<tls-auth>
%s
</tls-auth>`, ret, ta)
	}
	return []byte(ret), nil
}
