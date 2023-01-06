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

	isInit := IsInitialized()
	assert.False(t, isInit, "Initialize")

	err := Initialize()
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
	assert.NoError(t, err, "DeleteClient(test1")
	// no user error
	err = RevokeClient(name1)
	assert.Error(t, err, "DeleteClient(test1")
}
