package jwt

import (
	"hash"
	"sync"
)

type hashPool struct {
	pool *sync.Pool
}

func newHashPool() *hashPool {
	return &hashPool{
		pool: &sync.Pool{},
	}
}

func (p *hashPool) getHash(fn func() hash.Hash) hash.Hash {
	h := p.pool.Get()
	if h == nil {
		return fn()
	}
	return h.(hash.Hash)
}

func (p *hashPool) putHash(h hash.Hash) {
	h.Reset()
	p.pool.Put(h)
}
