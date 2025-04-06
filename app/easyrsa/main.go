package easyrsa

import (
	"bufio"
	"easyrsa-web-ui/app/config"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type EasyrsaClient struct {
	Identity       string
	Status         string
	Serial         string
	ExpireDate     time.Time
	RevokeDate     time.Time
	EnableRenew    bool
	EnableUnrevoke bool
}

func (e EasyrsaClient) IsEnableUnrevoke() bool {
	if e.Status != "Revoked" {
		return false
	}
	_, err := os.Stat(filepath.Join(config.Current.PkiPath, "revoked/private_by_serial/", e.Serial+".key"))
	return err == nil
}

func (e EasyrsaClient) IsEnableRenew() bool {
	if e.Status == "Revoked" {
		return false
	}
	date, err := GetCertRenew()
	if err != nil {
		return false
	}
	if time.Now().AddDate(0, 0, date).After(e.ExpireDate) {
		return true
	}
	return false
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

func pkiIndexPath() string {
	return filepath.Join(config.Current.PkiPath, "index.txt")
}

func easyrsaCmd() string {
	return fmt.Sprintf("%s --pki-dir=%s", filepath.Join(config.Current.Path, "easyrsa"), config.Current.PkiPath)
}

func copyFile(srcname, distname string) error {
	src, err := os.Open(srcname)
	if err != nil {
		return err
	}
	defer src.Close()

	dist, err := os.Create(distname)
	if err != nil {
		return err
	}
	defer dist.Close()

	_, err = io.Copy(dist, src)
	return err
}

func InitEasyrsa(force bool) error {
	_, err := os.Stat(config.Current.EasyrsaConfig.Path)
	if err == nil {
		if force {
			_ = os.RemoveAll(config.Current.EasyrsaConfig.Path)
		} else {
			logrus.Info(config.Current.EasyrsaConfig.Path + " already exist")
			return nil
		}
	}
	_ = os.Mkdir(config.Current.EasyrsaConfig.Path, 0755)
	err = execCmd(fmt.Sprintf("cd %s && curl -sL %s | tar -xzv --strip-components=1 -C .", config.Current.Path, config.Current.Package))
	if err != nil {
		return err
	}
	// INFO: support 3.2.1
	//if _, err = os.Stat(filepath.Join(config.Current.EasyrsaConfig.Path, "easyrsa-tools.lib")); err != nil {
	//	url := "https://raw.githubusercontent.com/OpenVPN/easy-rsa/master/easyrsa3/easyrsa-tools.lib"
	//	err = execCmd(fmt.Sprintf("cd %s && curl -O %s", config.Current.Path, url))
	//	if err != nil {
	//		return err
	//	}
	//}
	return nil
}

func IsInitialized() bool {
	_, err := os.Stat(config.Current.EasyrsaConfig.Path)
	if err != nil {
		return false
	}
	_, err = os.Stat(config.Current.PkiPath)
	return err == nil
}

func Initialize() error {
	err := InitEasyrsa(false)
	if err != nil {
		return err
	}
	err = execCmd(fmt.Sprintf("%s init-pki", easyrsaCmd()))
	if err != nil {
		return err
	}
	err = execCmd(fmt.Sprintf("echo \"ca\" | %s build-ca nopass", easyrsaCmd()))
	if err != nil {
		return err
	}
	err = execCmd(fmt.Sprintf("echo \"yes\" | %s build-server-full server nopass", easyrsaCmd()))
	if err != nil {
		return err
	}

	if config.Current.OpenvpnConfig.Support {
		err = execCmd(fmt.Sprintf("%s gen-dh", easyrsaCmd()))
		if err != nil {
			return err
		}
		err = execCmd(fmt.Sprintf("cd %s && openvpn --genkey --secret ta.key", config.Current.PkiPath))
		if err != nil {
			return err
		}
	}
	return nil
}

func GenCrl() error {
	return execCmd(fmt.Sprintf("%s gen-crl", easyrsaCmd()))
}

func execCmd(command string) error {
	logrus.Info("exec: " + command)
	cmd := exec.Command("sh", "-c", command)
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
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].Flag != ret[j].Flag {
			ip := 1
			jp := 1
			switch ret[i].Flag {
			case "E":
				ip = 0
			case "R":
				ip = 2
			}
			switch ret[j].Flag {
			case "E":
				jp = 0
			case "R":
				jp = 2
			}
			return ip < jp
		}
		if ret[i].RevoceDate != "" {
			return ret[i].RevoceDate > ret[j].RevoceDate
		}
		return ret[i].ExpireDate > ret[j].ExpireDate
	})
	return ret, nil
}

func readIndex() ([][]string, error) {
	f, err := os.Open(pkiIndexPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()

	b := bufio.NewReader(f)
	r := csv.NewReader(b)
	r.Comma = '\t'
	return r.ReadAll()
}

func writeIndex(list [][]string) error {
	f, err := os.Create(pkiIndexPath())
	if err != nil {
		return err
	}
	defer f.Close()

	for _, v := range list {
		_, _ = f.WriteString(fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n",
			v[0], v[1], v[2], v[3], v[4], v[5]))
	}
	return nil
}

func getKey(name string) (string, error) {
	ret, err := os.ReadFile(filepath.Join(config.Current.PkiPath, "private", name+".key"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func getCrt(name string) (string, error) {
	ret, err := os.ReadFile(filepath.Join(config.Current.PkiPath, "issued", name+".crt"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func GetCertRenew() (int, error) {
	vars, err := os.ReadFile(filepath.Join(config.Current.PkiPath, "vars"))
	if err != nil {
		return 30, nil
	}
	reg := regexp.MustCompile(`[^#]\sset_var\sEASYRSA_CERT_RENEW\s([0-9]+)`)
	result := reg.FindStringSubmatch(string(vars))
	if len(result) < 2 {
		return 30, nil
	}
	ret, err := strconv.Atoi(result[1])
	if err != nil {
		return 0, err
	}
	return ret, nil
}

func ServerCa() (string, error) {
	ret, err := os.ReadFile(filepath.Join(config.Current.PkiPath, "ca.crt"))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func ServerTa() (string, error) {
	ret, err := os.ReadFile(filepath.Join(config.Current.PkiPath, "ta.key"))
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
			Serial:     v.SerialNumber,
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
		item.EnableRenew = item.IsEnableRenew()
		item.EnableUnrevoke = item.IsEnableUnrevoke()
		ret = append(ret, item)
	}
	return ret, nil
}

func CreateClient(name string) error {
	reg := regexp.MustCompile(`^([a-zA-Z0-9_.-@])+$`)
	if !reg.MatchString(name) {
		return errors.New("username can only contains [a-zA-Z0-9_.-@]")
	}
	return execCmd(fmt.Sprintf("echo \"yes\" | %s build-client-full %s nopass", easyrsaCmd(), name))
}

func RevokeClient(name string) error {
	reg := regexp.MustCompile(`^([a-zA-Z0-9_.-@])+$`)
	if !reg.MatchString(name) {
		return errors.New("username can only contains [a-zA-Z0-9_.-@]")
	}
	return execCmd(fmt.Sprintf("echo \"yes\" | %s revoke %s && %s gen-crl", easyrsaCmd(), name, easyrsaCmd()))
}

func UnrevokeClient(serial string) error {
	modify := false
	l, err := readIndex()
	if err != nil {
		return err
	}
	for k, v := range l {
		if v[0] != "R" {
			continue
		}
		if serial != v[3] {
			continue
		}
		name := v[5][strings.Index(v[5], "=")+1:]
		err = copyFile(
			filepath.Join(config.Current.PkiPath, "revoked/certs_by_serial", v[3]+".crt"),
			filepath.Join(config.Current.PkiPath, "certs_by_serial", serial+".pem"))
		if err != nil {
			return err
		}
		err = os.Rename(
			filepath.Join(config.Current.PkiPath, "revoked/certs_by_serial", serial+".crt"),
			filepath.Join(config.Current.PkiPath, "issued", name+".crt"))
		if err != nil {
			return err
		}
		err = os.Rename(
			filepath.Join(config.Current.PkiPath, "revoked/private_by_serial", serial+".key"),
			filepath.Join(config.Current.PkiPath, "private", name+".key"))
		if err != nil {
			return err
		}
		err = os.Rename(
			filepath.Join(config.Current.PkiPath, "revoked/reqs_by_serial", serial+".req"),
			filepath.Join(config.Current.PkiPath, "reqs", name+".req"))
		if err != nil {
			return err
		}
		l[k][0] = "V"
		l[k][2] = ""
		modify = true
	}
	if modify {
		err = writeIndex(l)
		if err != nil {
			return err
		}
		return execCmd(fmt.Sprintf("%s gen-crl", easyrsaCmd()))
	}
	return errors.New("no revoked user")
}

func RenewClient(name string) error {
	reg := regexp.MustCompile(`^([a-zA-Z0-9_.-@])+$`)
	if !reg.MatchString(name) {
		return errors.New("username can only contains [a-zA-Z0-9_.-@]")
	}
	err := execCmd(fmt.Sprintf("echo \"yes\" | %s renew %s ", easyrsaCmd(), name))
	if err != nil {
		return err
	}
	return execCmd(fmt.Sprintf("echo \"yes\" | %s revoke-renewed %s && %s gen-crl", easyrsaCmd(), name, easyrsaCmd()))
}

func GetP12(name string) ([]byte, error) {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("openssl pkcs12 -export -passout pass: -inkey %s -in %s -certfile %s",
		filepath.Join(config.Current.PkiPath, "private", fmt.Sprintf("%s.key", name)),
		filepath.Join(config.Current.PkiPath, "issued", fmt.Sprintf("%s.crt", name)),
		filepath.Join(config.Current.PkiPath, "ca.crt")))
	return cmd.CombinedOutput()
}

func clientConfig() (string, error) {
	ret, err := os.ReadFile(config.Current.ClientConfig)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ret)), nil
}

func GetOvpn(name string) ([]byte, error) {
	if !config.Current.OpenvpnConfig.Support {
		return nil, errors.New("openvpn not support")
	}
	cc, err := clientConfig()
	if err != nil {
		return nil, err
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
	ret := fmt.Sprintf(`%s
<ca>
%s
</ca>
<cert>
%s
</cert>
<key>
%s
</key>`, cc, ca, crt, key)
	if ta != "" {
		ret = fmt.Sprintf(`%s
<tls-auth>
%s
</tls-auth>`, ret, ta)
	}
	return []byte(ret), nil
}
