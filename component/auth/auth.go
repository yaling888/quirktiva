package auth

import (
	"crypto/subtle"
	"sync"

	"github.com/samber/lo"
)

type Authenticator interface {
	Verify(user []byte, pass []byte) bool
	HasUser(user []byte) bool
	Users() []string
	RandomUser() *AuthUser
}

type AuthUser struct {
	User string
	Pass string
}

var _ Authenticator = (*inMemoryAuthenticator)(nil)

type inMemoryAuthenticator struct {
	storage   *sync.Map
	usernames []string
}

func (au *inMemoryAuthenticator) Verify(user []byte, pass []byte) bool {
	realPass, ok := au.storage.Load(string(user))
	return ok && subtle.ConstantTimeCompare(realPass.([]byte), pass) == 1
}

func (au *inMemoryAuthenticator) HasUser(user []byte) bool {
	_, ok := au.storage.Load(string(user))
	return ok
}

func (au *inMemoryAuthenticator) Users() []string {
	return au.usernames
}

func (au *inMemoryAuthenticator) RandomUser() *AuthUser {
	if au == nil || len(au.usernames) == 0 {
		return nil
	}

	user := lo.Sample(au.usernames)
	realPass, ok := au.storage.Load(user)
	if !ok {
		return nil
	}

	return &AuthUser{
		User: user,
		Pass: string(realPass.([]byte)),
	}
}

func NewAuthenticator(users []AuthUser) Authenticator {
	if len(users) == 0 {
		return nil
	}

	au := &inMemoryAuthenticator{storage: &sync.Map{}}
	usernames := make([]string, 0, len(users))
	for _, user := range users {
		au.storage.Store(user.User, []byte(user.Pass))
		usernames = append(usernames, user.User)
	}
	au.usernames = lo.Uniq(usernames)

	return au
}
