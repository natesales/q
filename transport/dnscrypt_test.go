package transport

import "time"

func dnscryptTransport() *DNSCrypt {
	d := &DNSCrypt{
		Common:      Common{Timeout: 1 * time.Second},
		ServerStamp: "sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	}
	return d
}
