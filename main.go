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

func report(msg string) {
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

func lookup(hostname string) (net.IP, bool, error) {
	addresses, err := net.LookupIP(hostname)
	if err != nil {
		return nil, false, fmt.Errorf("lookup %s: could not resolve", hostname)
	}

	for _, address := range addresses {
		if address.To16() != nil {
			return address, true, nil
		} else if address.To4() != nil {
			return address, false, nil
		}
	}

	return nil, false, fmt.Errorf("lookup %s: no valid address found", hostname)
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

func main() {
	var target net.IPAddr
	var conn *icmp.PacketConn
	var err error
	var ip6 bool
	var msg *icmp.Message
	var buffer []byte = make([]byte, 1500)

	for _, host := range hosts {
		target.IP, ip6, err = lookup(host)
		if err != nil {
			report(err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}

		if ip6 == true {
			conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
		} else {
			conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		}
		if err != nil {
			report(err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}
		defer conn.Close()

		err = conn.SetDeadline(time.Now().Add(time.Second * 5))
		if err != nil {
			report(err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}

		packet, err := generatePacket(ip6)
		if err != nil {
			report(err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}
		_, err = conn.WriteTo(packet, &target)
		if err != nil {
			report(err.Error())
			fmt.Printf("%s: %s\n", host, err.Error())
			continue
		}

		for {
			n, _, err := conn.ReadFrom(buffer)
			if err != nil {
				report(err.Error())
				fmt.Printf("%s: %s\n", host, err.Error())
				break
			}

			if ip6 == true {
				msg, err = icmp.ParseMessage(ProtocolIPv6ICMP, buffer[:n])
			} else {
				msg, err = icmp.ParseMessage(ProtocolICMP, buffer[:n])
			}
			if err != nil {
				report(err.Error())
				fmt.Printf("%s: %s\n", host, err.Error())
				continue
			}
			if msg.Type == ipv6.ICMPTypeEchoReply || msg.Type == ipv4.ICMPTypeEchoReply {
				fmt.Printf("%s: Everything is fine\n", host)
				break
			}
		}
	}

}
