package cachefile

import (
	"os"
	"sync"
	"time"

	"github.com/phuslu/log"
	"go.etcd.io/bbolt"

	"github.com/yaling888/quirktiva/component/profile"
	C "github.com/yaling888/quirktiva/constant"
)

var (
	fileMode os.FileMode = 0o666

	bucketSelected     = []byte("selected")
	bucketFakeip       = []byte("fakeip")
	bucketSubscription = []byte("subscription")
)

// CacheFile store and update the cache file
type CacheFile struct {
	DB *bbolt.DB
}

func (c *CacheFile) SetSelected(group, selected string) {
	if !profile.StoreSelected.Load() {
		return
	} else if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSelected)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(group), []byte(selected))
	})
	if err != nil {
		log.Warn().Err(err).Msgf("[CacheFile] write cache to %s failed", c.DB.Path())
		return
	}
}

func (c *CacheFile) SelectedMap() map[string]string {
	if !profile.StoreSelected.Load() {
		return nil
	} else if c.DB == nil {
		return nil
	}

	mapping := map[string]string{}
	_ = c.DB.View(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketSelected)
		if bucket == nil {
			return nil
		}

		c := bucket.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			mapping[string(k)] = string(v)
		}
		return nil
	})
	return mapping
}

func (c *CacheFile) PutFakeip(key, value []byte) error {
	if c.DB == nil {
		return nil
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		return bucket.Put(key, value)
	})
	if err != nil {
		log.Warn().Err(err).Msgf("[CacheFile] write cache to %s failed", c.DB.Path())
	}

	return err
}

func (c *CacheFile) DelFakeipPair(ip, host []byte) error {
	if c.DB == nil {
		return nil
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketFakeip)
		if err != nil {
			return err
		}
		err = bucket.Delete(ip)
		if len(host) > 0 {
			if err := bucket.Delete(host); err != nil {
				return err
			}
		}
		return err
	})
	if err != nil {
		log.Warn().Err(err).Msgf("[CacheFile] write cache to %s failed", c.DB.Path())
	}

	return err
}

func (c *CacheFile) GetFakeip(key []byte) []byte {
	if c.DB == nil {
		return nil
	}

	tx, err := c.DB.Begin(false)
	if err != nil {
		return nil
	}
	defer func(tx *bbolt.Tx) {
		_ = tx.Rollback()
	}(tx)

	bucket := tx.Bucket(bucketFakeip)
	if bucket == nil {
		return nil
	}

	return bucket.Get(key)
}

func (c *CacheFile) FlushFakeIP() error {
	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket := t.Bucket(bucketFakeip)
		if bucket == nil {
			return nil
		}
		return t.DeleteBucket(bucketFakeip)
	})
	return err
}

func (c *CacheFile) SetSubscription(key, value string) {
	if c.DB == nil {
		return
	}

	err := c.DB.Batch(func(t *bbolt.Tx) error {
		bucket, err := t.CreateBucketIfNotExists(bucketSubscription)
		if err != nil {
			return err
		}
		return bucket.Put([]byte(key), []byte(value))
	})
	if err != nil {
		log.Warn().Err(err).Msgf("[CacheFile] write cache to %s failed", c.DB.Path())
		return
	}
}

func (c *CacheFile) GetSubscription(key string) string {
	if c.DB == nil {
		return ""
	}

	tx, err := c.DB.Begin(false)
	if err != nil {
		return ""
	}
	defer func(tx *bbolt.Tx) {
		_ = tx.Rollback()
	}(tx)

	bucket := tx.Bucket(bucketSubscription)
	if bucket == nil {
		return ""
	}

	return string(bucket.Get([]byte(key)))
}

func (c *CacheFile) Close() error {
	return c.DB.Close()
}

// Cache return singleton of CacheFile
var Cache = sync.OnceValue(func() *CacheFile {
	options := bbolt.Options{Timeout: time.Second}
	db, err := bbolt.Open(C.Path.Cache(), fileMode, &options)
	switch err {
	case bbolt.ErrInvalid, bbolt.ErrChecksum, bbolt.ErrVersionMismatch:
		if err = os.Remove(C.Path.Cache()); err != nil {
			log.Warn().Err(err).Msg("[CacheFile] remove invalid cache file failed")
			break
		}
		log.Info().Msg("[CacheFile] remove invalid cache file and create new one")
		db, err = bbolt.Open(C.Path.Cache(), fileMode, &options)
	}
	if err != nil {
		log.Warn().Err(err).Msg("[CacheFile] open cache file failed")
	}

	return &CacheFile{
		DB: db,
	}
})
