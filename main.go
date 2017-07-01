package main

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	tiloApiSid       = getenv("TWILIO_API_SID")
	tiloApiAuthToken = getenv("TWILIO_API_AUTH_TOKEN")
	tiloApiFrom      = getenv("TWILIO_API_FROM")
	tiloSmsTo        = getenv("TWILIO_SMS_TO")
	hosts            = []string{"heise.de", "google.com", "twitter.com"}
	ProtocolIPv6ICMP = 58
	ProtocolICMP     = 1
)

func getenv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		panic("missing required environment variable " + name)
	}
	return v
}

func report(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args)
	values := url.Values{}
	values.Set("From", tiloApiFrom)
	values.Set("To", tiloSmsTo)
	values.Set("Body", msg)

	req, err := http.NewRequest("POST", "https://api.twilio.com/2010-04-01/Accounts/"+
		tiloApiSid+"/Messages", strings.NewReader(values.Encode()))
	if err != nil {
		fmt.Errorf("could not create request: %v", err)
	}
	req.SetBasicAuth(tiloApiSid, tiloApiAuthToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Errorf("could not send report: %v\n", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fmt.Printf("Report was rejected: %v\n", resp)
	}
	resp.Body.Close()
}

func generatePacket(ip6 bool) ([]byte, error) {
	data := make([]byte, 1337)
	var message icmp.Message
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}

	payload := icmp.Echo{
		ID:   os.Getpid() & 0xffff,
		Seq:  1,
		Data: data,
	}
	if ip6 == true {
		message = icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &payload,
		}
	} else {
		message = icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &payload,
		}
	}
	return message.Marshal(nil)
}

func sendv6Msg(ipAddr net.IP, host string) (success bool) {
	var conn *icmp.PacketConn
	var err error
	var msg *icmp.Message
	var buffer []byte = make([]byte, 1500)

	fmt.Printf("%s @ %v\n", host, ipAddr.String())

	success = false

	conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		report("%s: Could not create socket\n%s\n", host, err.Error())
		fmt.Printf("%s: %s\n", host, err.Error())
		return
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(time.Second * 5))
	if err != nil {
		report("%s: Could not set deadline for socket\n%s\n", host, err.Error())
		fmt.Printf("%s: %s\n", host, err.Error())
		return
	}

	packet, err := generatePacket(true)
	if err != nil {
		report("%s: Could not generate IP packet\n%s\n", host, err.Error())
		fmt.Printf("%s: %s\n", host, err.Error())
		return
	}

	addr, err := net.ResolveIPAddr("ip6", ipAddr.String())
	if err != nil {
		report("%s: Could not resolve IP\n%s\n", host, err.Error())
		fmt.Printf("%s: %s\n", host, err.Error())
		return
	}

	_, err = conn.WriteTo(packet, addr)
	if err != nil {
		report("%s: Could not send message\n%s\n", host, err.Error())
		fmt.Printf("%s: %s\n", host, err.Error())
		return
	}

	for {
		n, _, err := conn.ReadFrom(buffer)
		if err != nil {
			report("%s: Could not read reply\n%s\n", host, err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			break
		}

		msg, err = icmp.ParseMessage(ProtocolIPv6ICMP, buffer[:n])
		if err != nil {
			report("%s: Could no parse reply\n%s\n", host, err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}
		if msg.Type == ipv6.ICMPTypeEchoReply {
			return true
		}
	}
	return
}

func main() {
	var success bool

	for _, host := range hosts {
		recods, err := net.LookupIP(host)
		if err != nil {
			report("%s: Could not resolve host to IP\t%s\n", host, err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}
		success = false
		for _, record := range recods {
			if record.To16() != nil && record.To4() == nil {
				success = sendv6Msg(record, host)
			} else {
				fmt.Printf("v4 isn't implemented yet for %s @ %v\n", host, record)
			}
			if success == true {
				break
			}
		}
		if success == false {
			fmt.Printf("%s can't be reached\n", host)

		}
	}

}
