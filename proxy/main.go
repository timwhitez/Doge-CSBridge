package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/martian/v3"
	martianLog "github.com/google/martian/v3/log"
	"github.com/google/martian/v3/mitm"
	log "github.com/sirupsen/logrus"
)

var (
	port = flag.Int("port", 8888, "listen http port")
	secret,_ = base64.StdEncoding.DecodeString("Nlc2SUNTTUFRVElBTENVSTcySFQ0R0tXR1NCUVNNQ0U=")
)

func init() {
	martianLog.SetLevel(martianLog.Error)
	flag.Parse()
}

func main() {
	p := martian.NewProxy()
	defer p.Close()

	ca, privateKey, _ := mitm.NewAuthority("name", "org", 24*365*time.Hour)
	conf, _ := mitm.NewConfig(ca, privateKey)
	p.SetMITM(conf)

	//proxy, _ := url.Parse("http://localhost:8080")
	//p.SetDownstreamProxy(proxy)

	l, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", *port))
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("starting listen on %s", l.Addr().String())

	p.SetRequestModifier(new(T))

	p.SetResponseModifier(new(R))

	go p.Serve(l)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
}


type R struct {
	martian.ResponseModifier
}

func (R) ModifyResponse(resp *http.Response) error {
	res := resp
	otp := []byte(getotp())
	if resp.Body == nil{
		resp.Body = http.NoBody
		resp.ContentLength = 0
		*resp = *res
	}else{
		b, err := ioutil.ReadAll(resp.Body) //Read html
		fmt.Println("encResp: "+string(b))
		if err != nil || string(b) == ""{
			resp.Body = http.NoBody
			resp.ContentLength = 0
			*resp = *res
			return  nil
		}
		resp.Body.Close()
		b64Resp,err := base64.StdEncoding.DecodeString(string(b)[12:])
		if err != nil || string(b64Resp) == ""{
			resp.Body = http.NoBody
			resp.ContentLength = 0
			*resp = *res
			return  nil
		}
		rawResp,err := decrypt(b64Resp,otp)
		if err != nil || string(rawResp) == ""{
			resp.Body = http.NoBody
			resp.ContentLength = 0
			*resp = *res
			return  nil
		}
		fmt.Println("rawResp: "+string(rawResp))
		body := ioutil.NopCloser(bytes.NewReader(rawResp))
		resp.Body = body
		resp.ContentLength = int64(len(rawResp))
	}

	return nil
}


type T struct {
	martian.RequestModifier
}

func (T) ModifyRequest(req *http.Request) error {
	body, _ := ioutil.ReadAll(req.Body)
	fmt.Println("rawBody: "+string(body))
	u, _ := url.Parse(req.URL.String())

	hostu := u.Scheme+"://"+u.Host+"/"
	fmt.Println("rawHost: "+hostu)
	fmt.Println("rawURI: "+u.Path[1:])
	cipher,_ := encrypt(body,[]byte(getotp()))

	encBody := "%25PDF-1.7+ " + base64.StdEncoding.EncodeToString(cipher)
	fmt.Println("encBody: "+encBody)

	uri,_ := encrypt([]byte(u.Path[1:]),[]byte(getotp()))
	encodeuri := base64.RawURLEncoding.EncodeToString(uri)
	fmt.Println("encURL: "+hostu + encodeuri)
	newReq, _ := http.NewRequest(req.Method, hostu + encodeuri, strings.NewReader(encBody))

	newReq.URL , _ = url.Parse(hostu + encodeuri)
	newReq.Header = req.Header
	rawCookie := req.Header.Get("Cookie")
	fmt.Println("rawCookies: " + rawCookie)

	encCookieByte,_ := encrypt([]byte(rawCookie),[]byte(getotp()))
	encCookie := base64.RawURLEncoding.EncodeToString(encCookieByte)
	fmt.Println("encCookie: tz=America%2FLos_Angeles; _gh_sess=" + encCookie + "\n\n")
	newReq.Header.Set("Cookie", "tz=America%2FLos_Angeles; _gh_sess="+encCookie)

	//newReq.Header.Set("Url", req.URL.String())
	*req = *newReq
	return nil
}