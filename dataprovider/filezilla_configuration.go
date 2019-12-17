package dataprovider

import "fmt"
import "errors"
import "strings"
import "os"

import "github.com/antchfx/xmlquery"

import "crypto/sha512"
import "crypto/md5"
import "encoding/hex"

type FilezillaConfiguration struct {
    filezillaConfigFilePath string
}

type FilezillaUser struct {
    id int
    name string
    home string
    enabled bool
}

func NewFilezillaConfiguration(filezillaConfigFilePath string) *FilezillaConfiguration {
    return &FilezillaConfiguration {
        filezillaConfigFilePath: filezillaConfigFilePath,
    }
}

func (p FilezillaConfiguration) getUsers() ([]FilezillaUser, error) {
    f, err := os.Open(p.filezillaConfigFilePath)
    defer f.Close()

    if err != nil {
        return []FilezillaUser{}, err
    }

    doc, err := xmlquery.Parse(f)
    if err != nil {
        return []FilezillaUser{}, err
    }

    result := []FilezillaUser{}

    for i,n := range xmlquery.Find(doc, "//User") {
        user, err := p.getUserInternal(n)
        
        if err != nil {
            continue
        }
        
        user.id = i
        result = append(result, user)
    }

    return result, nil
}

func (p FilezillaConfiguration) getUserNode(username string) (*xmlquery.Node, *os.File) {
    f, err := os.Open(p.filezillaConfigFilePath)
    defer f.Close()

    doc, err := xmlquery.Parse(f)
    if err != nil {
        panic(err)
    }

    query := fmt.Sprintf("//User[@Name=\"%s\"]", username)
    user := xmlquery.FindOne(doc, query)
    return user, f
}

func (p FilezillaConfiguration) validateUserAndPass(username string, password string) bool {
    user, f := p.getUserNode(username)
    defer f.Close()
    
    if user == nil {
        return false
    }
    
    passHash := xmlquery.FindOne(user, "Option[@Name=\"Pass\"]").InnerText()
    salt_node := xmlquery.FindOne(user, "Option[@Name=\"Salt\"]")

    var salt string = "";
    if (salt_node == nil || salt_node.InnerText() == "") {
        salt = ""
    } else {
        salt = salt_node.InnerText()
    }

    var computedHash string

    // Select required hash method depending on resulting hash length
    // Argh I don't know if there are interfaces or pointers to functions in golang
    if len(passHash) == 32 {
        hasher := md5.New()
        hasher.Write([]byte(password))
        hasher.Write([]byte(salt))
        computedHash = hex.EncodeToString(hasher.Sum(nil))
    } else {
        hasher := sha512.New()
        hasher.Write([]byte(password))
        hasher.Write([]byte(salt))
        computedHash = hex.EncodeToString(hasher.Sum(nil))
    }

    return strings.ToUpper(computedHash) == strings.ToUpper(passHash)
}

func (p FilezillaConfiguration) getHomeDirectoryInternal(user *xmlquery.Node) (string, error) {
    // Get home dir
    for _, n := range xmlquery.Find(user, "Permissions/Permission") {
       isHomeNode := xmlquery.FindOne(n, "Option[@Name=\"IsHome\"]")
       if isHomeNode != nil && isHomeNode.InnerText() == "1" {
           return n.SelectAttr("Dir"), nil
       }
    }
    return "", errors.New("Cannot find home directory")
}

func (p FilezillaConfiguration) getHomeDirectory(username string) (string, error) {
    user, f := p.getUserNode(username)
    defer f.Close()
    return p.getHomeDirectoryInternal(user)
}

func (p FilezillaConfiguration) getUserInternal(user *xmlquery.Node) (FilezillaUser, error) {
    if user == nil {
        return FilezillaUser { id: -1, }, errors.New("Invalid argument: user")
    }
    isEnabled := xmlquery.FindOne(user, "Option[@Name=\"Enabled\"]")
    homeDir, err := p.getHomeDirectoryInternal(user)
    
    // Despite user exist, we cannot let them log in without home directory assigned
    if err != nil {
        return FilezillaUser{}, err
    }
    
    return FilezillaUser {
        name: user.SelectAttr("Name"),
        enabled: isEnabled == nil || isEnabled.InnerText() == "1",
        home: homeDir,
    }, nil
}

func (p FilezillaConfiguration) getUser(username string) (FilezillaUser, error) {
    users, err := p.getUsers()
    
    if err != nil {
        return FilezillaUser { id: -1, }, errors.New(fmt.Sprintf("Cannot get user list", username))
    }
    
    for _, user := range users {
        if user.name == username {
            return user, nil
        }
    }
    
    return FilezillaUser { id: -1, }, errors.New(fmt.Sprintf("No such user: %v", username))
}
