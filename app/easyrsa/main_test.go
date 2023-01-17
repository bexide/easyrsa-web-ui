package easyrsa

import (
	"easyrsa-web-ui/app/config"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMain(t *testing.T) {
	t.Cleanup(func() {
		os.RemoveAll(config.Current.PkiPath)
		os.RemoveAll(config.Current.Path)
	})

	os.Chdir("../..")

	config.Current.Path = "testrsa"
	config.Current.PkiPath = "testpki"
	config.Current.OpenvpnConfig.Support = false

	isInit := IsInitialized()
	assert.False(t, isInit, "Initialize")

	err := InitEasyrsa()
	assert.NoError(t, err, "InitEasyrsa()")
	if err != nil {
		return
	}

	n, err := os.Create("testrsa/vars")
	assert.NoError(t, err, "os.Create()")
	if err != nil {
		return
	}
	defer n.Close()
	_, err = n.WriteString(`set_var EASYRSA_CA_EXPIRE 15
set_var EASYRSA_CERT_EXPIRE 14
set_var EASYRSA_CRL_DAYS 13
set_var EASYRSA_CERT_RENEW	15
`)
	assert.NoError(t, err, "io.Write()")
	if err != nil {
		return
	}

	err = Initialize()
	assert.NoError(t, err, "Initialize()")
	if err != nil {
		return
	}

	_, err = ServerCa()
	assert.NoError(t, err, "ServerCa()")

	name1 := "test1"
	err = CreateClient(name1)
	assert.NoError(t, err, "CreateClient(test1)")
	// same name error
	err = CreateClient(name1)
	assert.Error(t, err, "CreateClient(test1)")

	err = RevokeClient(name1)
	assert.NoError(t, err, "RevokeClient(test1)")
	// no user error
	err = RevokeClient(name1)
	assert.Error(t, err, "RevokeClient(test1)")

	err = UnrevokeClient(name1)
	assert.NoError(t, err, "UnrevokeClient(test1)")
	// no user error
	err = UnrevokeClient(name1)
	assert.Error(t, err, "UnrevokeClient(test1)")

	days, err := GetCertRenew()
	assert.NoError(t, err, "GetCertRenew()")
	assert.Equal(t, days, 15, "GetCertRenew()")

	name2 := "test2"
	err = CreateClient(name2)
	assert.NoError(t, err, "CreateClient(test2)")

	err = RenewClient(name2)
	assert.NoError(t, err, "RenewClient(test2)")

}
