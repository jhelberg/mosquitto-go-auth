package backends

import (
	"fmt"
	"strconv"
	"strings"
        "sync"

	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// This is the postgres-personal edition of the postgresql backend.
// The difference between the postgres and postgresp backend is that
// the postgresp code uses the credentials of the mosquitto-user
// to authenticate against the database and to run the ACL-queries
// under this login-user as well.

// This allows a fully Row-Level-Security data-set to function whithout
// any need for super-users (hence the option for the query to check
// for someone being 'the' super-user is removed)

// The postgres-backend used the OpenDatabase-call for opening a
// connection, assuming this happens only once and must succeed. The
// whole retry-mechanism is dropped for the postgresp-backend, as
// opening a new connection happens all the time and queries may not succeed
// for some end-users, where it may still work for others. Hence no retries
// and no disconnects upon failed queries.

// The assumption is that there may be many mosquitto-end-users, but
// that few make a lot of calls. Hence we cache some (configurable) amount
// of database connections based upon the connection-string.
// Also, as the context of accessing the ACL has no password available,
// username/passwords are cached as well upon verifying if a user exists.
// All username/passwords are cached in memory, allowing the mosquitto process
// to grow a lot. Mind though that although 50000 different end-users will
// result in a hashmap with 50k entries, the size of this hashmap will
// hardly be more than a few megabytes.

// TODO: remove database connection for every user once in a while to make
//       sure this user is still allowed to connect. Configurable and
//       defaults to 20 minutes or so.
// TODO: hash the password, as it may leak and is inspectable by root
// TODO: re-connect in case a query fails because of a disconnect from the
//       other side. 2 seconds back-off time seems reasonable, but will
//       block other procesing of messages. Maybe some go-routine should
//       handle processing the failed call, queing these while handling the
//       re-connect.

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
	CCS            int
}

// we store a map username -> dbconnection for not re-connecting all
// the time. It has limited size, beyond this, re-connects will
// happen all the time for new users.
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

// postgresp maintains it's own opendatabase-call as the original one
// retries connecting if it fails.
// as we use end-user credentials (different for each end-user of the mosquitto product),
// failing can be quite normal and is just an error, nothing fatal. It just means
// this user cannot play.
var chit = 0
var nopens = 0
func (o Postgresp) openDatabase(dsn, engine string) (*sqlx.DB, error) {
	nopens++
	connsaccessmutex.Lock()
	if db, ok := userconns[ dsn ]; ok {
		connsaccessmutex.Unlock()
		chit++
		log.Printf( "(postgresp:openDatabase) userconns hit: %d/%d", chit, nopens )
		return db, nil
	}
	connsaccessmutex.Unlock()
	log.Printf( "(postgresp:openDatabase) opening database connection" )
	db, err := sqlx.Open(engine, dsn)
	if err != nil {
		return nil, errors.Wrap(err, "database connection error")
	}

	if err = db.Ping(); err != nil {
		log.Errorf("ping database %s error: %s", engine, err)
		db.Close()
		return nil, err
	}
	if len( userconns ) < o.CCS  {
		connsaccessmutex.Lock()
		userconns[ dsn ] = db
		connsaccessmutex.Unlock()
	} else {
		log.Printf( "(postgresp:openDatabase) userconns permanent no-hit as len is %d", len( userconns ) )
	}
	return db, nil
}
func (o Postgresp) closeDatabase(dsn string, db *sqlx.DB) {
	connsaccessmutex.Lock()
	if _, ok := userconns[ dsn ]; !ok {
		connsaccessmutex.Unlock()
		if db != nil {
			db.Close()
		}
	} else {
		connsaccessmutex.Unlock()
	}
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
		CCS:            50,
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

	if ccs, ok := authOpts["pgp_conncachesize"]; ok {
		cachesize, err := strconv.Atoi( ccs )
		if err != nil {
			log.Warnf("invalid postgres connection cache size options: %s", err)
		} else {
			postgres.CCS = cachesize
		}
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
	DB, err := o.openDatabase(connStr, "postgres")
	o.closeDatabase(connStr, DB)
	if err == nil { // only cache username/password in case connecting succeeds
		passaccessmutex.Lock()
		// strings are immutable in Go, except... when they come from a C program, the bytes in password
		// are re-used later by the C program, hence the copying of the content of the string.
		userpasss[ username[0:1] + username[1:] ] = password[0:1] + password[1:] // simplest way to copy string contents
		passaccessmutex.Unlock()
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
	connstring := ""
	passaccessmutex.Lock()
	if p, ok := userpasss[ username ]; ok {
		passaccessmutex.Unlock()
		var err error
		log.Debugf("PGP CheckAcl client %s using %s", clientid, username )
		connstring = o.connectString( username, p, o.SSLCert != "" || o.SSLKey != "" )
		DB, err = o.openDatabase( connstring, "postgres")
		if err != nil {
			log.Debugf("PGP CheckAcl logon error from client %s: user %s not valid", clientid, username)
			passaccessmutex.Lock()
			delete( userpasss, username )
			passaccessmutex.Unlock()
			o.closeDatabase( connstring, DB )
			return false, err
		}
	} else {
		passaccessmutex.Unlock()
		log.Debugf("PGP CheckAcl no password remembered for user %s", username)
		return false, nil
	}

	// one of AclQuery and PAclQuery is not empty (see first if in this function)
	if o.PAclQuery != "" {
		var ok bool

		err := DB.Select(&ok, o.PAclQuery, username, acc, topic)
		o.closeDatabase( connstring, DB )

		if err != nil {
			log.Debugf("PGP check pacl error: %s", err)
			return false, err
		}
		return ok, nil
	}

	if o.AclQuery != "" {
		var acls []string

		err := DB.Select(&acls, o.AclQuery, username, acc)
		o.closeDatabase( connstring, DB )

		if err != nil {
			log.Debugf("PGP check acl error: %s", err)
			return false, err
		}

		for _, acl := range acls {
			aclTopic := strings.Replace(acl, "%c", clientid, -1)
			aclTopic = strings.Replace(aclTopic, "%u", username, -1)
			if topics.Match(aclTopic, topic) {
				return true, nil
			}
		}
		return false, nil
        }
	// not reached
	return false, nil
}

//GetName returns the backend's name
func (o Postgresp) GetName() string {
	return "Postgresp"
}

//Halt has nothing to do
func (o Postgresp) Halt() {
}
