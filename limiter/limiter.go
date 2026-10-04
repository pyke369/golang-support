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
	mode     int
	capacity int
	ttl      time.Duration
	limit    float64
	burst    int
	mu       sync.Mutex
	lru      *list.List
	entries  map[string]*list.Element
}

func New(mode, capacity int, limit float64, extra ...int) (out *Limiter) {
	capacity = min(8<<10, max(1, capacity))
	out = &Limiter{
		mode:     mode,
		capacity: capacity,
		limit:    limit,
		burst:    1,
		lru:      list.New(),
		entries:  map[string]*list.Element{},
	}
	if mode == TTL {
		out.capacity, out.ttl = 8<<10, time.Duration(capacity)*time.Second
	}
	if len(extra) != 0 && extra[0] >= 1 {
		out.burst = extra[0]
	}

	return
}

func (l *Limiter) get(subject string) (out *entry) {
	if l.limit < 0 || l.capacity < 1 || l.capacity > 8<<10 {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if e, exists := l.entries[subject]; exists && (l.mode != TTL || time.Since(e.Value.(*entry).active) < l.ttl) {
		l.lru.MoveToFront(e)
		out = e.Value.(*entry)
		out.active = time.Now()

	} else {
		switch l.mode {
		case Fixed:
			if len(l.entries) >= l.capacity {
				return nil
			}

		case LRU:
			for len(l.entries) >= l.capacity {
				e := l.lru.Back()
				if e == nil {
					break
				}
				if v := l.lru.Remove(e); v != nil {
					delete(l.entries, v.(*entry).subject)
				}
			}

		case TTL:
			for e := l.lru.Back(); e != nil; {
				prev := e.Prev()
				if time.Since(e.Value.(*entry).active) < l.ttl {
					break
				}
				if v := l.lru.Remove(e); v != nil {
					delete(l.entries, v.(*entry).subject)
				}
				e = prev
			}
			for len(l.entries) >= l.capacity {
				e := l.lru.Back()
				if e == nil {
					break
				}
				if v := l.lru.Remove(e); v != nil {
					delete(l.entries, v.(*entry).subject)
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
	timeout := 30 * time.Second
	if len(extra) != 0 && extra[0] > 0 && extra[0] <= 30*time.Second {
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
