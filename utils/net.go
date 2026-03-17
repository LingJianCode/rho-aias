package utils

import (
	"archive/tar"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	localIPs []string = []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"233.252.0.0/24",
		"240.0.0.0/4",
		"255.255.255.255/32",
	}
	localIPNets []*net.IPNet
)

func init() {
	for _, ip := range localIPs {
		_, ipNet, err := net.ParseCIDR(ip)
		if err != nil {
			continue
		}
		localIPNets = append(localIPNets, ipNet)
	}
}

func IsLocalIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	ipNet := net.ParseIP(ip)
	for _, localIPNet := range localIPNets {
		if localIPNet.Contains(ipNet) {
			return true
		}
	}
	return false
}

func GetDefaultInterface() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal("Failed to get network interfaces:", err)
		return ""
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
					if ipnet.IP.To4() != nil {
						return iface.Name
					}
				}
			}
		}
	}
	log.Fatal("No suitable network interface found")
	return ""
}

func ValidateInterface(iface string) bool {
	_, err := net.InterfaceByName(iface)
	return err == nil
}

func IsValidMAC(mac string) bool {
	_, err := net.ParseMAC(mac)
	return err == nil
}

func IsValidIPv4(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() != nil
}

func IsValidIPv6(ip string) bool {
	return net.ParseIP(ip) != nil && net.ParseIP(ip).To4() == nil
}

func GenerateUUID() string {
	return uuid.New().String()
}

type IPType uint8

const (
	IPTypeUnknown  IPType = 0
	IPTypeIPv4     IPType = 1
	IPTypeIPV4CIDR IPType = 2
	IPTypeIPv6     IPType = 3
	IPTypeIPv6CIDR IPType = 4
	IPTypeMAC      IPType = 5
)

func ParseStringToIPType(value string) IPType {
	value = strings.TrimSpace(value)
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		ip := net.ParseIP(value)
		if ip == nil {
			_, err := net.ParseMAC(value)
			if err != nil {
				return IPTypeUnknown
			}
			return IPTypeMAC
		}
		if ip.To4() != nil {
			return IPTypeIPv4
		} else {
			return IPTypeIPv6
		}
	}
	if ipNet.IP.To4() != nil {
		return IPTypeIPV4CIDR
	} else if ipNet.IP.To16() != nil {
		return IPTypeIPv6CIDR
	}
	return IPTypeUnknown
}

// ip地址为大端，ebpf规定前缀为主机字节序(x86为小端)
func ParseValueToBytes(value string) ([]byte, IPType, error) {
	value = strings.TrimSpace(value)
	// try to parse as CIDR
	_, ipNet, err := net.ParseCIDR(value)
	if err != nil {
		// try to parse as IP
		ip := net.ParseIP(value)
		if ip == nil {
			// try to parse as MAC
			macAddr, err := net.ParseMAC(value)
			if err != nil {
				return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s", value)
			}

			return macAddr, IPTypeMAC, nil
		}
		if ip.To4() != nil {
			return ip.To4(), IPTypeIPv4, nil
		} else if ip.To16() != nil {
			return ip.To16(), IPTypeIPv6, nil
		} else {
			return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s", value)
		}
	}
	ones, _ := ipNet.Mask.Size()
	if ipNet.IP.To4() != nil && len(ipNet.IP) == net.IPv4len {
		var bytes [8]byte
		binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
		copy(bytes[4:], ipNet.IP.To4())
		return bytes[:], IPTypeIPV4CIDR, nil
	} else if ipNet.IP.To16() != nil && len(ipNet.IP) == net.IPv6len {
		var bytes [20]byte
		binary.LittleEndian.PutUint32(bytes[:4], uint32(ones))
		copy(bytes[4:], ipNet.IP.To16())
		return bytes[:], IPTypeIPv6CIDR, nil
	} else {
		return nil, IPTypeUnknown, fmt.Errorf("invalid value: %s", value)
	}
}

func GenerateRandomString(length int) string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, length)
	for i := range b {
		b[i] = chars[r.Intn(len(chars))]
	}
	return string(b)
}

func DownloadGeoIPTarGZ(url string, geoipPath string) error {
	client := &http.Client{
		Timeout: 5 * time.Minute,
	}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}
	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar: %w", err)
		}
		if strings.HasSuffix(header.Name, ".mmdb") {
			out, err := os.Create(geoipPath)
			if err != nil {
				return fmt.Errorf("failed to create file: %w", err)
			}
			defer out.Close()

			if _, err := io.Copy(out, tr); err != nil {
				return fmt.Errorf("failed to write file: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("no .mmdb file found in archive")
}
