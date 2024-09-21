package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"time"

	"golang.org/x/net/proxy"
)

const (
	IP_API         = "https://api.ipify.org/?format=json"
	TorrcCfgString = `
VirtualAddrNetwork 10.0.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
DNSPort 5353
ControlPort 9051
RunAsDaemon 1
`
	resolvString = "nameserver 127.0.0.1"
)

var (
	nonTorNetworks = []string{
		"192.168.1.0/24", "192.168.0.0/24", "172.16.11.0/24", "172.16.12.0/24", "10.6.6.0/24",
		"10.20.20.0/24", "103.143.170.0/24", "103.105.52.0/24", "188.114.96.0/24", "188.114.97.0/24",
		"172.67.151.0/24", "104.21.48.0/24", "104.18.30.2/24",
	}
)

func main() {
	action := flag.String("action", "", "Specify action: start, stop, switch")
	flag.Parse()

	switch *action {
	case "start":
		output, err := startTorghost()
		if err != nil {
			log.Fatalf("Failed to start torghost: %v", err)
		}
		fmt.Println(output)

	case "stop":
		output, err := stopTorghost()
		if err != nil {
			log.Fatalf("Failed to stop torghost: %v", err)
		}
		fmt.Println(output)

	case "switch":
		output, err := switchTorghost()
		if err != nil {
			log.Fatalf("Failed to switch torghost: %v", err)
		}
		fmt.Println(output)

	default:
		log.Fatal("Invalid action specified. Please use -action=start|stop|switch")
	}

	log.Fatal(http.ListenAndServe(":8080", nil))
}

func startTorghost() (string, error) {
	var output string

	output += "Always check for updates using -u option\n"

	if err := runCommand("sudo", "cp", "/etc/resolv.conf", "/etc/resolv.conf.bak"); err != nil {
		return "", fmt.Errorf("error copying resolv.conf: %v", err)
	}

	if _, err := os.Stat("/etc/tor/torghostrc"); os.IsNotExist(err) {
		if err := createTorrcFile(); err != nil {
			return "", fmt.Errorf("error creating torrc file: %v", err)
		}
		output += "Writing torcc file\n[done]\n"
	} else {
		output += "Torrc file already configured\n"
	}

	if _, err := os.Stat("/etc/resolv.conf"); os.IsNotExist(err) {
		if err := createResolvConfFile(); err != nil {
			return "", fmt.Errorf("error creating resolv.conf: %v", err)
		}
		output += "Configuring DNS resolv.conf file..\n[done]\n"
	} else {
		output += "DNS resolv.conf file already configured\n"
	}

	if err := stopTorService(); err != nil {
		return "", fmt.Errorf("error stopping tor service: %v", err)
	}
	output += "Stopping tor service [done]\n"

	if err := startTorDaemon(); err != nil {
		return "", fmt.Errorf("error starting tor daemon: %v", err)
	}
	output += "Starting new tor daemon [done]\n"

	if err := setupIPTablesRules(); err != nil {
		return "", fmt.Errorf("error setting up iptables rules: %v", err)
	}
	output += "Setting up iptables rules [done]\n"

	currentIP, err := fetchCurrentIP()
	if err != nil {
		return "", fmt.Errorf("error fetching current IP: %v", err)
	}
	output += "CURRENT IP : " + currentIP + "\n"

	return output, nil
}

func stopTorghost() (string, error) {
	var output string

	output += "STOPPING torghost\n"

	if err := runCommand("mv", "/etc/resolv.conf.bak", "/etc/resolv.conf"); err != nil {
		return "", fmt.Errorf("error restoring resolv.conf: %v", err)
	}

	if err := flushIPTables(); err != nil {
		return "", fmt.Errorf("error flushing iptables: %v", err)
	}
	output += "Flushing iptables [done]\n"

	if err := restartNetworkManager(); err != nil {
		return "", fmt.Errorf("error restarting network manager: %v", err)
	}
	output += "Restarting Network manager [done]\n"

	currentIP, err := fetchCurrentIP()
	if err != nil {
		return "", fmt.Errorf("error fetching current IP: %v", err)
	}
	output += "CURRENT IP : " + currentIP + "\n"

	return output, nil
}

func switchTorghost() (string, error) {
	var output string

	output += "Please wait...\n"
	time.Sleep(7 * time.Second)

	output += "Requesting new circuit...\n"
	if err := requestNewCircuit(); err != nil {
		return "", fmt.Errorf("error requesting new circuit: %v", err)
	}
	output += "Requesting new circuit [done]\n"

	currentIP, err := fetchCurrentIP()
	if err != nil {
		return "", fmt.Errorf("error fetching current IP: %v", err)
	}
	output += "CURRENT IP : " + currentIP + "\n"

	return output, nil
}

func createTorrcFile() error {
	file, err := os.Create("/etc/tor/torghostrc")
	if err != nil {
		return fmt.Errorf("error creating torrc file: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(TorrcCfgString)
	if err != nil {
		return fmt.Errorf("error writing torrc file: %v", err)
	}

	return nil
}

func createResolvConfFile() error {
	file, err := os.Create("/etc/resolv.conf")
	if err != nil {
		return fmt.Errorf("error creating resolv.conf: %v", err)
	}
	defer file.Close()

	_, err = file.WriteString(resolvString)
	if err != nil {
		return fmt.Errorf("error writing resolv.conf: %v", err)
	}

	return nil
}

func stopTorService() error {
	// Stop Tor service
	cmd := exec.Command("sudo", "systemctl", "stop", "tor")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error stopping tor service: %v", err)
	}

	// Kill Tor process on port 9051
	cmd = exec.Command("sudo", "fuser", "-k", "9051/tcp")
	if err := cmd.Run(); err != nil {
		// Log error for troubleshooting
		log.Printf("error killing tor process: %v", err)
	}

	return nil
}

func startTorDaemon() error {
	cmd := exec.Command("sudo", "-u", "debian-tor", "tor", "-f", "/etc/tor/torghostrc")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error starting tor daemon: %v", err)
	}

	// Optional: Add logging or additional checks here if needed

	return nil
}

func setupIPTablesRules() error {
	cmd := exec.Command("bash", "-c", `
    NON_TOR="192.168.1.0/24 192.168.0.0/24 172.16.11.0/24 172.16.12.0/24 10.6.6.0/24 10.20.20.0/24 103.143.170.0/24 103.105.52.0/24 23.207.121.0/24 140.82.121.0/24 188.114.96.0/24 188.114.97.0/24 34.117.59.2/24 173.239.8.0/24 52.142.124.0/24 172.67.151.0/24 104.21.48.0/24 104.18.30.0/24 104.18.12.0/24"
	TOR_UID=$(id -ur debian-tor)
	TRANS_PORT="9040"

	iptables -F
	iptables -t nat -F

	iptables -t nat -A OUTPUT -m owner --uid-owner $TOR_UID -j RETURN
	iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
	for NET in $NON_TOR 127.0.0.0/9 127.128.0.0/10; do
	 iptables -t nat -A OUTPUT -d $NET -j RETURN
	done
	iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $TRANS_PORT
    iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $TRANS_PORT
    iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $TRANS_PORT
 
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
    iptables -A OUTPUT -p tcp --dport 8080 -j ACCEPT
    iptables -A OUTPUT -p icmp -j ACCEPT
    iptables -A OUTPUT -p udp -j ACCEPT

	iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	for NET in $NON_TOR 127.0.0.0/8; do
	 iptables -A OUTPUT -d $NET -j ACCEPT
	done
	iptables -A OUTPUT -m owner --uid-owner $TOR_UID -j ACCEPT
	iptables -A OUTPUT -j REJECT
	`)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error setting up iptables rules: %v", err)
	}

	return nil
}

func flushIPTables() error {
	cmd := exec.Command("bash", "-c", `
	iptables -P INPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -t nat -F
	iptables -t mangle -F
	iptables -F
	iptables -X
	`)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error flushing iptables: %v", err)
	}

	return nil
}

func restartNetworkManager() error {
	if err := runCommand("sudo", "service", "network-manager", "restart"); err != nil {
		return fmt.Errorf("error restarting network manager: %v", err)
	}

	return nil
}

func fetchCurrentIP() (string, error) {
	var ipTxt string
	for {
		jsonRes, err := getIP()
		if err != nil {
			continue
		}
		ipTxt = jsonRes["ip"].(string)
		break
	}
	return ipTxt, nil
}

func getIP() (map[string]interface{}, error) {
	resp, err := http.Get(IP_API)
	if err != nil {
		return nil, fmt.Errorf("error getting IP from API: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("error decoding JSON response: %v", err)
	}

	return result, nil
}

func requestNewCircuit() error {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		return fmt.Errorf("error creating SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", "127.0.0.1:9051")
	if err != nil {
		return fmt.Errorf("error dialing SOCKS5 proxy: %v", err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	_, err = conn.Write([]byte("AUTHENTICATE\r\n"))
	if err != nil {
		return fmt.Errorf("error writing to SOCKS5 proxy: %v", err)
	}

	response := make([]byte, 128)
	_, err = conn.Read(response)
	if err != nil {
		return fmt.Errorf("error reading from SOCKS5 proxy: %v", err)
	}

	_, err = conn.Write([]byte("SIGNAL NEWNYM\r\n"))
	if err != nil {
		return fmt.Errorf("error sending SIGNAL NEWNYM: %v", err)
	}

	_, err = conn.Read(response)
	if err != nil {
		return fmt.Errorf("error reading response to SIGNAL NEWNYM: %v", err)
	}

	return nil
}

func runCommand(command string, args ...string) error {
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error running command %s: %v", command, err)
	}
	return nil
}
