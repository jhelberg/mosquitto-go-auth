package backends

import (
	//"fmt"
	//"time"

	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// OpenDatabase opens the database and performs a ping to make sure the
// database is up.
// Taken from brocaar's lora-app-server: https://github.com/brocaar/lora-app-server
func OpenDatabase(dsn, engine string, tries int) (*sqlx.DB, error) {

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
