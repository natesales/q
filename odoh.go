/*
This implementation is based on https://github.com/cloudflare/odoh-client-go, per the MIT license below:

The MIT License

Copyright (c) 2019-2020, Cloudflare, Inc. and Christopher Wood. All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/cloudflare/odoh-go"
	"github.com/miekg/dns"
)

func buildURL(s, defaultPath string) *url.URL {
	if //goland:noinspection HttpUrlsUsage
	!strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "http://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("failed to parse url: %v", err)
	}
	if u.Path == "" {
		u.Path = defaultPath
	}
	return u
}

func resolveObliviousQuery(query odoh.ObliviousDNSMessage, targetIP string, proxy string, client *http.Client) (response odoh.ObliviousDNSMessage, err error) {
	serializedQuery := query.Marshal()
	p := buildURL(proxy, "/proxy")
	t := buildURL(targetIP, "/dns-query")
	qry := p.Query()
	if qry.Get("targethost") == "" {
		qry.Set("targethost", t.Host)
	}
	if qry.Get("targetpath") == "" {
		qry.Set("targetpath", t.Path)
	}
	p.RawQuery = qry.Encode()

	req, err := http.NewRequest(http.MethodPost, p.String(), bytes.NewBuffer(serializedQuery))
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	req.Header.Set("Content-Type", "application/oblivious-dns-message")
	req.Header.Set("Accept", "application/oblivious-dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	responseHeader := resp.Header.Get("Content-Type")
	bodyBytes, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}
	if responseHeader != "application/oblivious-dns-message" {
		return odoh.ObliviousDNSMessage{}, fmt.Errorf("did not obtain the correct headers from %v with response %v", targetIP, string(bodyBytes))
	}

	odohQueryResponse, err := odoh.UnmarshalDNSMessage(bodyBytes)
	if err != nil {
		return odoh.ObliviousDNSMessage{}, err
	}

	return odohQueryResponse, nil
}

func odohQuery(query dns.Msg, proxy string, target string) (*dns.Msg, error) {
	// Query ODoH configs on target
	req, err := http.NewRequest(http.MethodGet, buildURL(target, "/.well-known/odohconfigs").String(), nil)
	if err != nil {
		return nil, err
	}

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	odohConfigs, err := odoh.UnmarshalObliviousDoHConfigs(bodyBytes)
	if err != nil {
		return nil, err
	}

	if len(odohConfigs.Configs) == 0 {
		err := errors.New("target provided no valid odoh configs")
		fmt.Println(err)
		return nil, err
	}
	odohConfig := odohConfigs.Configs[0]

	packedDnsQuery, err := query.Pack()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	odohQuery := odoh.CreateObliviousDNSQuery(packedDnsQuery, 0)
	odnsMessage, queryContext, err := odohConfig.Contents.EncryptQuery(odohQuery)
	if err != nil {
		return nil, err
	}

	client = http.Client{}
	odohMessage, err := resolveObliviousQuery(odnsMessage, target, proxy, &client)
	if err != nil {
		return nil, err
	}

	decryptedResponse, err := queryContext.OpenAnswer(odohMessage)
	if err != nil {
		return nil, err
	}

	msg := &dns.Msg{}
	err = msg.Unpack(decryptedResponse)
	if err != nil {
		return nil, err
	}
	return msg, nil
}
