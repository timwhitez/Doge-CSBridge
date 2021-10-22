package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var secret,_ = base64.StdEncoding.DecodeString("Nlc2SUNTTUFRVElBTENVSTcySFQ0R0tXR1NCUVNNQ0U=")

// w表示response对象，返回给客户端的内容都在对象里处理
// r表示客户端请求对象，包含了请求头，请求参数等等
func index(w http.ResponseWriter, r *http.Request) {
	otp := []byte(getotp())
	body, _ := ioutil.ReadAll(r.Body)
	fmt.Println("encBody: "+string(body))
	body,_ = base64.StdEncoding.DecodeString(string(body)[12:])
	plaintext,err := decrypt(body,otp)
	if err == nil {
		fmt.Println("rawBody: "+string(plaintext))
		fmt.Println("encURI: "+r.RequestURI[1:])
		uris,_ := base64.RawURLEncoding.DecodeString(r.RequestURI[1:])
		uri,err := decrypt(uris,otp)
		if err == nil {
			fmt.Println("rawURI: "+string(uri))
			fmt.Println("Method: "+r.Method)
			newReq, _ := http.NewRequest(r.Method, "http://127.0.0.1:9999/"+string(uri), strings.NewReader(string(plaintext)))
			newReq.URL, _ = url.Parse("http://127.0.0.1:9999/" + string(uri))
			newReq.Body = io.NopCloser(strings.NewReader(string(plaintext)))
			newReq.Header = r.Header

			encCookie := strings.Split(r.Header.Get("Cookie"),"tz=America%2FLos_Angeles; _gh_sess=")[1]
			fmt.Println("encCookie: tz=America%2FLos_Angeles; _gh_sess=" + encCookie)

			encCookieByte,_ := base64.RawURLEncoding.DecodeString(encCookie)
			rawCookie,_ := decrypt(encCookieByte,otp)
			fmt.Println("rawCookie: " + string(rawCookie))
			newReq.Header.Set("Cookie", string(rawCookie))

			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
			client := &http.Client{Transport: tr,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				}}

			resp, _ := client.Do(newReq)
			fmt.Println(resp.Status)
			body, _ = ioutil.ReadAll(resp.Body)
			fmt.Println("rawResp: "+string(body))

			encResp,_ := encrypt(body,[]byte(getotp()))
			encRespstr := "%25PDF-1.7+ " + base64.StdEncoding.EncodeToString(encResp)
			fmt.Println("encResp: "+encRespstr + "\n\n")
			// 往w里写入内容，就会在浏览器里输出
			//fmt.Fprintf(w, encRespstr)
			io.WriteString(w, encRespstr)
		}
	}else{
		flushBody(w) // 立即flush并断开连接
	}
}

func main() {
	// 设置路由，如果访问/，则调用index方法
	http.HandleFunc("/", index)

	// 启动web服务，监听9090端口
	err := http.ListenAndServe(":9090", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}


func flushBody(w http.ResponseWriter) bool {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
		if hj, ok := w.(http.Hijacker); ok { // 从ResponseWriter获取链接控制权
			if conn, _, err := hj.Hijack(); err == nil {
				if err := conn.Close(); err == nil {
					return true
				}
			}
		}
	}
	return false
}