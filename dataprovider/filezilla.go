package dataprovider

import (
	"errors"
	"fmt"
	"sync"
	"sort"

	"github.com/drakkan/sftpgo/logger"
)

var (
	errFilezillaProviderClosed = errors.New("filezilla provider is closed")
)

var (
	errFilezillaUnsupportsThisFeature = errors.New("Unsupported. Please use FileZilla Server Interface for all user-related configuration.")
)

type FilezillaProviderHandle struct {
	isClosed bool
	filezilla *FilezillaConfiguration
	lock  *sync.Mutex
}

// FilezillaProvider auth provider for a memory store
type FilezillaProvider struct {
	dbHandle *FilezillaProviderHandle
}

func initializeFilezillaProvider() error {
	provider = FilezillaProvider{
		dbHandle: &FilezillaProviderHandle{
			isClosed:  false,
			filezilla: NewFilezillaConfiguration(config.Name),
			lock:      new(sync.Mutex),
		},
	}
	return nil
}

func (p FilezillaProvider) filezillaUserToUser(fzUser FilezillaUser) User {
	user := User {
		ID: int64(fzUser.id),
		Username: fzUser.name,
		HomeDir: fzUser.home,
		Password: "",
		Permissions: []string { PermAny },
	}
	if fzUser.enabled {
		user.Status = 1
	}
	return user
}

func (p FilezillaProvider) checkAvailability() error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errFilezillaProviderClosed
	}
	return nil
}

func (p FilezillaProvider) close() error {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return errFilezillaProviderClosed
	}
	p.dbHandle.isClosed = true
	return nil
}

func (p FilezillaProvider) validateUserAndPass(username string, password string) (User, error) {
	var user User
	if len(password) == 0 {
		return user, errors.New("Credentials cannot be null or empty")
	}
	user, err := p.userExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
		return user, err
	}
	if p.dbHandle.filezilla.validateUserAndPass(username, password) {
		return user, nil
	}
	
	err = errors.New("Invalid password")
	providerLog(logger.LevelWarn, "error authenticating user: %v, error: %v", username, err)
	return User{}, err
}

func (p FilezillaProvider) validateUserAndPubKey(username string, pubKey string) (User, string, error) {
	var user User
	return user, "", errFilezillaUnsupportsThisFeature
}

func (p FilezillaProvider) getUserByID(ID int64) (User, error) {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errFilezillaProviderClosed
	}
	
	fzUsers, err := p.dbHandle.filezilla.getUsers()
	
	if err != nil {
		return User{}, err
	}
	
	if ID < int64(len(fzUsers)){
		fzUser := fzUsers[ID]
		return p.filezillaUserToUser(fzUser), nil
	}
	
	return User{}, &RecordNotFoundError{err: fmt.Sprintf("user with ID %v does not exist", ID)}
}

func (p FilezillaProvider) updateLastLogin(username string) error {
	// Quitely do nothing
	return nil
}

func (p FilezillaProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return errFilezillaUnsupportsThisFeature
}

func (p FilezillaProvider) getUsedQuota(username string) (int, int64, error) {
	return 0, 0, nil
}

func (p FilezillaProvider) addUser(user User) error {
	return errFilezillaUnsupportsThisFeature
}

func (p FilezillaProvider) updateUser(user User) error {
	return errFilezillaUnsupportsThisFeature
}

func (p FilezillaProvider) deleteUser(user User) error {
	return errFilezillaUnsupportsThisFeature
}

func (p FilezillaProvider) getUsers(limit int, offset int, order string, username string) ([]User, error) {
	fzUsers, err := p.dbHandle.filezilla.getUsers()
	
	if err != nil {
		return []User{}, err
	}
	
	if order == "ASC" {
		sort.SliceStable(fzUsers, func(i, j int) bool {
			return fzUsers[i].name < fzUsers[j].name
		})
	} else {
		sort.SliceStable(fzUsers, func(i, j int) bool {
			return fzUsers[i].name > fzUsers[j].name
		})
	}
	
	users := []User{}
	
	for i, fzUser := range fzUsers {
		if i <= offset {
			continue
		}
		
		user := p.filezillaUserToUser(fzUser)
		users = append(users, user)
		if len(users) >= limit {
			break
		}
	}
	
	return users, nil
}

func (p FilezillaProvider) userExists(username string) (User, error) {
	p.dbHandle.lock.Lock()
	defer p.dbHandle.lock.Unlock()
	if p.dbHandle.isClosed {
		return User{}, errFilezillaProviderClosed
	}
	fzUser, err := p.dbHandle.filezilla.getUser(username)
	
	if err != nil {
		return User{}, err
	}
	
	if fzUser.id < 0 {
		return User{}, errors.New("No such user")
	}
	
	user := p.filezillaUserToUser(fzUser)
	return user, nil
}

func (p FilezillaProvider) getNextID() int64 {
	fzUsers, err := p.dbHandle.filezilla.getUsers()
	
	if err != nil {
		return -1
	}
	
	return int64(len(fzUsers))
}
