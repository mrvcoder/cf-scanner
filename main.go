package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

type Config struct {
	TestDomain       string   `json:"test_domain"`
	TestPath         string   `json:"test_path"`
	TcpTimeout       int      `json:"tcp_timeout"`
	HttpTimeout      int      `json:"http_timeout"`
	SslTimeout       int      `json:"ssl_timeout"`
	MaxWorkers       int      `json:"max_workers"`
	TestDownload     bool     `json:"test_download"`
	DownloadSize     int      `json:"download_size"`
	Port             int      `json:"port"`
	ExpectedHttpCode int      `json:"expected_http_code"`
	Subnets          []string `json:"subnets"`
}

type Result struct {
	IP        string
	Level     int
	Ping      string
	Speed     string
	IsPremium bool
}

type Scanner struct {
	conf         *Config
	results      []Result
	lvlCounts    map[int]int
	premiumCount int
	testedCount  int
	totalIPs     int
	history      []string
	threadStates []string
	lock         sync.Mutex
	startTime    time.Time
}

// Regex to extract time from ping output (e.g., time=120 ms)
var pingRegex = regexp.MustCompile(`time=([0-9.]+)`)

func main() {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)

	configFile, err := os.Open("config.json")
	if err != nil {
		gologger.Fatal().Msgf("Could not open config.json: %v", err)
	}
	defer configFile.Close()

	var conf Config
	if err := json.NewDecoder(configFile).Decode(&conf); err != nil {
		gologger.Fatal().Msgf("Could not parse config.json: %v", err)
	}

	s := &Scanner{
		conf:         &conf,
		lvlCounts:    make(map[int]int),
		threadStates: make([]string, conf.MaxWorkers),
		startTime:    time.Now(),
	}

	for i := range s.threadStates {
		s.threadStates[i] = "IDLE"
	}

	s.Execute()
}

func (s *Scanner) Execute() {
	// Clear previous results
	f, _ := os.Create("working_ips.txt")
	if f != nil {
		f.Close()
	}

	var ips []string
	for _, cidr := range s.conf.Subnets {
		expanded := expandCIDR(cidr)
		if expanded != nil {
			ips = append(ips, expanded...)
		}
	}
	s.totalIPs = len(ips)

	ipChan := make(chan string)
	var wg sync.WaitGroup

	stopUI := make(chan bool)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				s.drawUI()
			case <-stopUI:
				return
			}
		}
	}()

	for i := 0; i < s.conf.MaxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for ip := range ipChan {
				res, ok := s.testIP(ip, workerID)

				s.lock.Lock()
				s.testedCount++
				s.threadStates[workerID] = "IDLE"
				if ok {
					s.results = append(s.results, res)
					s.lvlCounts[res.Level]++

					statusTag := "✅          "
					if res.IsPremium {
						statusTag = "💎 PREMIUM "
						s.premiumCount++
					}

					line := fmt.Sprintf("%-11s | LVL %d | %-15s | %-8s | %-10s", statusTag, res.Level, res.IP, res.Ping, res.Speed)
					s.history = append(s.history, line)
					if len(s.history) > 10 {
						s.history = s.history[1:]
					}

					out, _ := os.OpenFile("working_ips.txt", os.O_APPEND|os.O_WRONLY, 0644)
					if out != nil {
						out.WriteString(line + "\n")
						out.Close()
					}
				}
				s.lock.Unlock()
			}
		}(i)
	}

	go func() {
		for _, ip := range ips {
			ipChan <- ip
		}
		close(ipChan)
	}()

	wg.Wait()
	stopUI <- true
	s.drawUI()
}

func (s *Scanner) testIP(ip string, workerID int) (Result, bool) {
	res := Result{IP: ip, Level: 0, Ping: "---", Speed: "---", IsPremium: false}
	addr := fmt.Sprintf("%s:%d", ip, s.conf.Port)

	// L0: Shell ICMP Ping (Non-root friendly)
	s.setStatus(workerID, ip, "L0: PING")
	// -c 1 (1 packet), -W 1 (1 second timeout)
	out, err := exec.Command("ping", "-c", "1", "-W", "1", ip).Output()
	if err == nil {
		match := pingRegex.FindStringSubmatch(string(out))
		if len(match) > 1 {
			res.Ping = match[1] + "ms"
		}
	} else {
		res.Ping = "timeout"
	}

	// L1: TCP Dial
	s.setStatus(workerID, ip, "L1: TCP")
	conn, err := net.DialTimeout("tcp", addr, time.Duration(s.conf.TcpTimeout)*time.Second)
	if err != nil {
		return res, false
	}
	res.Level = 1
	defer conn.Close()

	// L2: SSL Handshake
	s.setStatus(workerID, ip, "L2: SSL")
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         s.conf.TestDomain,
		InsecureSkipVerify: true,
	})
	tlsConn.SetDeadline(time.Now().Add(time.Duration(s.conf.SslTimeout) * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		return res, true
	}
	res.Level = 2

	// L3/L4: HTTP Request
	s.setStatus(workerID, ip, "L3: HTTP")
	client := &http.Client{
		Transport: &http.Transport{
			DialTLS: func(network, addr string) (net.Conn, error) { return tlsConn, nil },
		},
		Timeout: time.Duration(s.conf.HttpTimeout) * time.Second,
	}

	url := fmt.Sprintf("https://%s%s", s.conf.TestDomain, s.conf.TestPath)
	resp, err := client.Get(url)
	if err != nil {
		return res, true
	}
	defer resp.Body.Close()

	res.Level = 4
	if resp.StatusCode == s.conf.ExpectedHttpCode {
		res.IsPremium = true
	}

	// L5: Download Speed
	if s.conf.TestDownload {
		s.setStatus(workerID, ip, "L5: DL")
		dlStart := time.Now()
		written, _ := io.CopyN(io.Discard, resp.Body, int64(s.conf.DownloadSize))
		dur := time.Since(dlStart).Seconds()
		if written > 0 && dur > 0 {
			res.Level = 5
			res.Speed = fmt.Sprintf("%.1fKB/s", float64(written)/1024/dur)
		}
	}

	return res, true
}

func (s *Scanner) setStatus(id int, ip, status string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.threadStates[id] = fmt.Sprintf("[%s] %s", ip, status)
}

func (s *Scanner) drawUI() {
	s.lock.Lock()
	defer s.lock.Unlock()

	percent := 0.0
	if s.totalIPs > 0 {
		percent = float64(s.testedCount) / float64(s.totalIPs) * 100
	}
	bar := fmt.Sprintf("[%s%s] %.1f%%", strings.Repeat("█", int(40*percent/100)), strings.Repeat("░", 40-int(40*percent/100)), percent)

	fmt.Print("\033[H\033[2J")
	fmt.Println("  ______  ________         ______   ______   ______  __    __  __    __  ________  _______  ")
	fmt.Println(" /      \\|        \\       /      \\ /      \\ /      \\|  \\  |  \\|  \\  |  \\|        \\|       \\ ")
	fmt.Println("|  $$$$$$\\ $$$$$$$$      |  $$$$$$\\  $$$$$$\\  $$$$$$\\ $$$\\ | $$| $$$\\ | $$| $$$$$$$$| $$$$$$$\\")
	fmt.Println("| $$   \\$$| $$__          \\$$    \\| $$   \\$$| $$__| $$ $$$$\\| $$| $$$$\\| $$| $$__    | $$__| $$")
	fmt.Println("| $$      | $$  \\          _\\$$$$$$\\ $$      | $$    $$ $$ \\$$ $$| $$ \\$$ $$| $$  \\   | $$    $$")
	fmt.Println("| $$   __ | $$$$$         |  \\__| $$ $$   __ | $$$$$$$$ $$  \\$$$$| $$  \\$$$$| $$$$$    | $$$$$$$\\")
	fmt.Println("| $$__/  \\| $$             \\$$    $$ $$__/  \\| $$  | $$ $$   \\$$$| $$   \\$$$| $$_____ | $$  | $$")
	fmt.Println(" \\$$    $$| $$              \\$$$$$$ \\$$    $$| $$  | $$ $$    \\$$| $$    \\$$| $$     \\| $$  | $$")
	fmt.Println("  \\$$$$$$  \\$$               \\$$$$$$  \\$$$$$$ \\$$   \\$$ \\$$     \\ \\$$     \\  \\$$$$$$$$ \\$$   \\$$")
	fmt.Println(strings.Repeat("=", 95))
	fmt.Printf(" PROGRESS: %s | %d/%d IPs\n", bar, s.testedCount, s.totalIPs)
	fmt.Println(strings.Repeat("=", 95))
	fmt.Printf("🎯 Target    : %-30s | 💎 Premium   : %d\n", s.conf.TestDomain, s.premiumCount)
	fmt.Printf("📡 Port      : %-30d | ✅ Total OK  : %d\n", s.conf.Port, len(s.results))
	fmt.Println(strings.Repeat("-", 95))
	fmt.Println("Active Threads Monitor (Top 10):")
	for i := 0; i < 10 && i < len(s.threadStates); i++ {
		fmt.Printf(" 🧵 #%03d : %s\n", i, s.threadStates[i])
	}
	fmt.Println(strings.Repeat("=", 82))
}

func expandCIDR(cidr string) []string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
