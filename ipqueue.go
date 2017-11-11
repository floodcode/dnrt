package dnrt

import "net"
import "errors"

type IPQueue struct {
	ranges     []IPRange
	currentIPs []net.IP
	rangeIndex int
	ipIndex    int
}

func NewIPQueue(ranges []IPRange) IPQueue {
	queue := IPQueue{
		ranges:     ranges,
		currentIPs: []net.IP{},
		rangeIndex: -1,
		ipIndex:    -1,
	}
	queue.incrementRange()
	return queue
}

func (q *IPQueue) Next() (net.IP, error) {
	q.ipIndex++

	if len(q.currentIPs) <= q.ipIndex+1 {
		incremented := q.incrementRange()

		if !incremented {
			return nil, errors.New("no more IPs in queue")
		}
	}

	return q.currentIPs[q.ipIndex], nil
}

func (q *IPQueue) incrementRange() bool {
	incremented := false

	for !incremented {
		var err error

		if len(q.ranges) <= q.rangeIndex+1 {
			return false
		}

		q.rangeIndex++

		q.ipIndex = 0
		q.currentIPs, err = q.ranges[q.rangeIndex].GetAll()
		if err == nil {
			return true
		}
	}

	return false
}
