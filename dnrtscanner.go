package dnrt

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type DNRTScanner struct {
	ipQueue      IPQueue
	ipQueueMutex sync.Mutex
	ports        []uint16
	timeout      time.Duration
	threadsCount int
	wg           sync.WaitGroup
	callback     BruteCallback
}

func NewDNRTScanner() DNRTScanner {
	return DNRTScanner{
		ipQueue:      NewIPQueue([]IPRange{}),
		ipQueueMutex: sync.Mutex{},
		ports:        []uint16{80},
		timeout:      time.Millisecond * 150,
		threadsCount: 10,
		callback:     func(BruteResult) {},
	}
}

func (s *DNRTScanner) SetThreadsCount(threadsCount int) {
	s.threadsCount = threadsCount
}

func (s *DNRTScanner) SetTimeout(timeout time.Duration) {
	s.timeout = timeout
}

func (s *DNRTScanner) SetPorts(ports []uint16) {
	s.ports = ports
}

func (s *DNRTScanner) SetBruteCallback(callback BruteCallback) {
	s.callback = callback
}

func (s *DNRTScanner) SetIPsByStringList(list string) {
	lines := strings.Split(list, "\n")
	ranges := []IPRange{}

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		rng, rngError := getRangeByString(line)
		if rngError != nil {
			continue
		}

		ranges = append(ranges, rng)
	}

	s.ipQueue = NewIPQueue(ranges)
	time.Sleep(time.Millisecond)
}

func (s *DNRTScanner) Scan() {
	for i := 0; i < s.threadsCount; i++ {
		s.wg.Add(1)
		go s.processIP()
	}

	s.wg.Wait()
}

func (s *DNRTScanner) processIP() {
	defer s.wg.Done()

	for true {
		s.ipQueueMutex.Lock()
		ip, err := s.ipQueue.Next()
		s.ipQueueMutex.Unlock()

		if err != nil {
			return
		}

		for _, port := range s.ports {
			addressString := fmt.Sprintf("%s:%d", ip.String(), port)
			conn, err := net.DialTimeout("tcp", addressString, s.timeout)
			if err == nil {
				s.processOpenPort(ip, port)
				conn.Close()
			}
		}
	}
}

func (s *DNRTScanner) processOpenPort(ip net.IP, port uint16) {
	var bruteforcer Bruteforcer

	switch port {
	case 22:
		bruteforcer = NewBruteforcer(ServiceSSH, s.callback)
	}

	bruteforcer.brute(ip, port)
}
