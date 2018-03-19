package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

/* This program generates a 4096-bit RSA keypair using random.org HTTP API */

func main() {

	rs, err := newRandomSource("https://www.random.org/integers/", 10000)
	// rs, err := newRandomSource("http://localhost:8080/integers/", 10000)
	if err != nil {
		log.Fatal(err)
	}

	privateKey, err := rsa.GenerateKey(rs, 4096)
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(&privateKey.PublicKey)

	err = ioutil.WriteFile("rsa_private", privateKeyBytes, 0666)
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile("rsa_public", publicKeyBytes, 0666)
	if err != nil {
		log.Fatal(err)
	}
}

type randomSource struct {
	numbers      []byte
	server       string
	requestLimit int
}

func newRandomSource(server string, requestLimit int) (*randomSource, error) {
	rs := &randomSource{server: server, requestLimit: requestLimit}
	err := rs.replenish()
	return rs, err
}

func (rs *randomSource) Read(p []byte) (n int, err error) {
	err = rs.replenish()
	if err != nil {
		return 0, err
	}
	n = copy(p, rs.numbers)
	rs.numbers = rs.numbers[n:]
	return n, nil
}

func (rs *randomSource) replenish() error {
	if len(rs.numbers) == 0 {
		return makeRandomRequest(rs.server, rs.requestLimit, &rs.numbers)
	}
	return nil
}

func makeRandomRequest(server string, count int, appendTo *[]byte) error {
	url := fmt.Sprintf("%s?num=%d&min=%d&max=%d&col=1&base=10&format=plain&rnd=new",
		server, count, -1000000000, 1000000000)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Status %v %s", resp.Status, body)
	}
	err = nil
	for err == nil {
		var x int32
		var n int
		n, err = fmt.Fscanf(resp.Body, "%d\n", &x)
		if n == 1 {
			*appendTo = append(*appendTo,
				byte((x>>16)&0xFF),
				byte((x>>8)&0xFF),
				byte(x&0xFF),
			)
		}
	}
	return nil
}
