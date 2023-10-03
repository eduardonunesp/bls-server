package internal

import (
	"sync"

	"github.com/eduardonunesp/bls-server/commons/bls"
)

type MemoryDB struct {
	mu sync.Mutex
	m  map[string]*bls.AugMessage
}

func NewMemoryDB() *MemoryDB {
	return &MemoryDB{
		m: make(map[string]*bls.AugMessage),
	}
}

func (db *MemoryDB) Get(key string) (*bls.AugMessage, bool) {
	db.mu.Lock()
	defer db.mu.Unlock()

	val, ok := db.m[key]
	return val, ok
}

func (db *MemoryDB) Set(key string, val *bls.AugMessage) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.m[key] = val
}

func (db *MemoryDB) Delete(key string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	delete(db.m, key)
}

func (db *MemoryDB) Keys() []string {
	db.mu.Lock()
	defer db.mu.Unlock()

	var keys []string
	for k := range db.m {
		keys = append(keys, k)
	}
	return keys
}

func (db *MemoryDB) Len() int {
	db.mu.Lock()
	defer db.mu.Unlock()

	return len(db.m)
}

func (db *MemoryDB) Close() {}
