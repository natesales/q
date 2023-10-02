package transport

import "time"

func dnscryptTransport() *DNSCrypt {
	d := &DNSCrypt{
		ServerStamp: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
		Timeout:     1 * time.Second,
	}
	return d
}
