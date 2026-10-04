package limiter

import (
	"container/list"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	Fixed int = iota
	LRU
	TTL
)

type entry struct {
	subject string
	limiter *rate.Limiter
	active  time.Time
}

type Limiter struct {
	mode    int
	prune   int
	limit   float64
	mu      sync.Mutex
	lru     *list.List
	entries map[string]*list.Element
}

func New(mode, prune int, limit float64) *Limiter {
	return &Limiter{
		mode:    mode,
		prune:   prune,
		limit:   limit,
		lru:     list.New(),
		entries: map[string]*list.Element{},
	}
}

func (l *Limiter) get(subject string) (out *entry) {
	if l.limit < 0 || l.prune < 1 || l.prune > 16<<10 {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if e, exists := l.entries[subject]; exists && (l.mode != TTL || time.Since(e.Value.(*entry).active) < time.Duration(l.prune)*time.Second) {
		l.lru.MoveToFront(e)
		out = e.Value.(*entry)
		out.active = time.Now()

	} else {
		switch l.mode {
		case Fixed:
			if len(l.entries) >= l.prune {
				return nil
			}

		case LRU:
			if len(l.entries) >= l.prune {
				if e := l.lru.Back(); e != nil {
					if e := l.lru.Remove(e); e != nil {
						delete(l.entries, e.(*entry).subject)
					}
				}
			}

		case TTL:
			for e := l.lru.Back(); e != nil; e = e.Prev() {
				if time.Since(e.Value.(*entry).active) < time.Duration(l.prune)*time.Second {
					break
				}
				if e := l.lru.Remove(e); e != nil {
					delete(l.entries, e.(*entry).subject)
				}
			}
		}

		out = &entry{subject: subject, limiter: rate.NewLimiter(rate.Limit(l.limit), 1), active: time.Now()}
		l.entries[subject] = l.lru.PushFront(out)
	}

	return
}

func (l *Limiter) Allow(subject string) bool {
	e := l.get(subject)
	if e == nil {
		return false
	}

	return e.limiter.Allow()
}

func (l *Limiter) AllowDelay(subject string) (pass bool, delay time.Duration) {
	e := l.get(subject)
	if e == nil {
		return false, 0
	}

	reserve := e.limiter.Reserve()
	if !reserve.OK() {
		return false, 0
	}
	delay = reserve.Delay()
	if delay != 0 {
		reserve.Cancel()
		return false, delay
	}

	return true, 0
}

func (l *Limiter) Wait(subject string, extra ...time.Duration) bool {
	e := l.get(subject)
	if e == nil {
		return false
	}
	timeout := time.Duration(0)
	if len(extra) != 0 && extra[0] > 0 {
		timeout = extra[0]
	}

	reserve := e.limiter.Reserve()
	if !reserve.OK() {
		return false
	}
	delay := reserve.Delay()
	if delay == 0 {
		return true
	}
	if timeout != 0 && delay > timeout {
		reserve.Cancel()
		time.Sleep(timeout)
		return false
	}
	time.Sleep(delay)

	return true
}
