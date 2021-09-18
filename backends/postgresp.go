package backends

import (
	"fmt"
	"strings"
        "sync"

	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//Postgresp holds all fields of the postgresp db configuration.
type Postgresp struct {
	Host           string
	Port           string
	DBName         string
	UserQuery      string
	AclQuery       string
	PAclQuery      string
	SSLMode        string
	SSLCert        string
	SSLKey         string
	SSLRootCert    string

	connectTries int
}

// we store a map username -> dbconnection for not re-connecting all
// the time. This is not implemented yet!
// Note that connections are cleaned up after a while by timed-functions
// hence the mutex.
var	userconns = make( map[ string ]*sqlx.DB )
var     connsaccessmutex = sync.RWMutex{}

// we store a map username -> password for later connections,
// both the username and password come from C-calls and contain pointers to
// bytes, not copies! Hence, see further down, the password is _copied_ before
// putting it into the map userpasss. If not, the password will change later into
// something one cannot logon with. The brdige between C and Go should do that.
var	userpasss = make( map[ string ]string )
// we don't know if mosquitto calls these functions in a multi-threaded fashion.
// if so, we protect userpasss by a RWMutex. If not, too bad, some cycles are lost.
var     passaccessmutex = sync.RWMutex{}

func openDatabase(dsn, engine string, tries int) (*sqlx.DB, error) {

	db, err := sqlx.Open(engine, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "database connection error")
	}

	if err = db.Ping(); err != nil {
		log.Errorf("ping database %s error: %s", engine, err)
		db.Close()
		return nil, err
	}
	return db, nil
}

func NewPostgresp(authOpts map[string]string, logLevel log.Level ) (Postgresp, error) {
	log.SetLevel(logLevel)

	//Set defaults for postgresp

	pgOk := true
	missingOptions := ""

	var postgres = Postgresp{
		Host:           "localhost",
		Port:           "5432",
		SSLMode:        "disable",
		AclQuery:       "",
		PAclQuery:      "",
		connectTries:   -1,
	}

	if host, ok := authOpts["pg_host"]; ok {
		postgres.Host = host
	}

	if port, ok := authOpts["pg_port"]; ok {
		postgres.Port = port
	}

	if dbName, ok := authOpts["pg_dbname"]; ok {
		postgres.DBName = dbName
	} else {
		pgOk = false
		missingOptions += " pg_dbname"
	}

	if userQuery, ok := authOpts["pg_userquery"]; ok {
		postgres.UserQuery = userQuery
	} else {
		pgOk = false
		missingOptions += " pg_userquery"
	}

	if aclQuery, ok := authOpts["pg_aclquery"]; ok {
		postgres.AclQuery = aclQuery
	}

	if paclQuery, ok := authOpts["pgp_aclquery"]; ok {
		postgres.PAclQuery = paclQuery
	}

	if sslmode, ok := authOpts["pg_sslmode"]; ok {
		postgres.SSLMode = sslmode
	} else {
		postgres.SSLMode = "disable"
	}

	if sslCert, ok := authOpts["pg_sslcert"]; ok {
		postgres.SSLCert = sslCert
	}

	if sslKey, ok := authOpts["pg_sslkey"]; ok {
		postgres.SSLKey = sslKey
	}

	if sslCert, ok := authOpts["pg_sslrootcert"]; ok {
		postgres.SSLCert = sslCert
	}

	//Exit if any mandatory option is missing.
	if !pgOk {
		return postgres, errors.Errorf("PGP backend error: missing options: %s", missingOptions)
	}

	return postgres, nil
}

//GetUser checks that the username can login with the given credentials
func (o Postgresp) GetUser(username, password, clientid string) (bool, error) {

	connStr := o.connectString( username, password, o.SSLCert != "" || o.SSLKey != "" )
	DB, err := openDatabase(connStr, "postgres", o.connectTries)
	if err == nil {
		passaccessmutex.Lock()
		// strings are immutable in Go, except... when they come from a C program, the bytes in password
		// are re-used later by the C program, hence the copying of the content of the string.
		userpasss[ username[0:1] + username[1:] ] = password[0:1] + password[1:] // simplest way to copy string contents
		passaccessmutex.Unlock()
		DB.Close()
		return true, nil
	} else {
		log.Debugf("PGP GetUser logon error from client %s: user %s not valid", clientid, username)
		return false, nil
	}
	return false, nil
}

func (o Postgresp) connectString( username, password string, checkSSL bool ) string {
	connStr := fmt.Sprintf("user=%s password=%s dbname=%s host=%s port=%s", username, password, o.DBName, o.Host, o.Port)
	if (o.SSLMode == "verify-ca" || o.SSLMode == "verify-full") && checkSSL {
		connStr = fmt.Sprintf("%s sslmode=verify-ca sslcert=%s sslkey=%s sslrootcert=%s", connStr, o.SSLCert, o.SSLKey, o.SSLRootCert)
	} else if o.SSLMode == "require" {
		connStr = fmt.Sprintf("%s sslmode=require", connStr)
	} else {
		connStr = fmt.Sprintf("%s sslmode=disable", connStr)
	}
	return connStr
}

//GetSuperuser checks that the username meets the superuser query.
// in postgresp (and in a GDPR-compliant world) there is no concept of a superuser
func (o Postgresp) GetSuperuser(username string) (bool, error) {

	return false, nil
}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Postgresp) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	// PAclQuery to be implemented! Wil be used as a replacement for AclQuery
	//If there's no acl query, assume all privileges for all users.
	if o.PAclQuery == "" && o.AclQuery == "" {
		return true, nil
	}
	var DB *sqlx.DB
	passaccessmutex.Lock()
	if p, ok := userpasss[ username ]; ok {
		passaccessmutex.Unlock()
		var err error
		log.Debugf("PGP CheckAcl client %s using %s", clientid, username )
		DB, err = openDatabase( o.connectString( username, p, o.SSLCert != "" || o.SSLKey != "" ), "postgres", o.connectTries )
		if err != nil {
			log.Debugf("PGP CheckAcl logon error from client %s: user %s not valid", clientid, username)
			return false, err
		}
	} else {
		passaccessmutex.Unlock()
		log.Debugf("PGP CheckAcl no password remembered for user %s", username)
		return false, nil
	}

	if o.PAclQuery != "" {
		var ok bool

		err := DB.Select(&ok, o.PAclQuery, username, acc, topic)

		if err != nil {
			log.Debugf("PGP check pacl error: %s", err)
			DB.Close()
			return false, err
		}

		DB.Close()
		return ok, nil
	}

	if o.AclQuery != "" {
		var acls []string

		err := DB.Select(&acls, o.AclQuery, username, acc)

		if err != nil {
			log.Debugf("PGP check acl error: %s", err)
			DB.Close()
			return false, err
		}

		DB.Close()
		for _, acl := range acls {
			aclTopic := strings.Replace(acl, "%c", clientid, -1)
			aclTopic = strings.Replace(aclTopic, "%u", username, -1)
			if topics.Match(aclTopic, topic) {
				return true, nil
			}
		}
        }
	return false, nil

}

//GetName returns the backend's name
func (o Postgresp) GetName() string {
	return "Postgresp"
}

//Halt has nothing to do
func (o Postgresp) Halt() {
}
