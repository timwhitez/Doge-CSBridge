package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	//"io"
	"net"
	"strings"
	"time"
)

var firstTime time.Time

type GoogleAuth struct {
}

func NewGoogleAuth() *GoogleAuth {
	return &GoogleAuth{}
}

func (this *GoogleAuth) un() int64 {
	return firstTime.UnixNano() / 1000 / 30
}

func (this *GoogleAuth) hmacSha1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	if total := len(data); total > 0 {
		h.Write(data)
	}
	return h.Sum(nil)
}

func (this *GoogleAuth) base32encode(src []byte) string {
	return base32.StdEncoding.EncodeToString(src)
}

func (this *GoogleAuth) base32decode(s string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(s)
}

func (this *GoogleAuth) toBytes(value int64) []byte {
	var result []byte
	mask := int64(0xFF)
	shifts := [8]uint16{56, 48, 40, 32, 24, 16, 8, 0}
	for _, shift := range shifts {
		result = append(result, byte((value>>shift)&mask))
	}
	return result
}

func (this *GoogleAuth) toUint32(bts []byte) uint32 {
	return (uint32(bts[0]) << 24) + (uint32(bts[1]) << 16) +
		(uint32(bts[2]) << 8) + uint32(bts[3])
}

func (this *GoogleAuth) oneTimePassword(key []byte, data []byte) uint32 {
	hash := this.hmacSha1(key, data)
	offset := hash[len(hash)-1] & 0x0F
	hashParts := hash[offset : offset+4]
	hashParts[0] = hashParts[0] & 0x7F
	number := this.toUint32(hashParts)
	return number % 1000000
}

// 获取秘钥
func (this *GoogleAuth) GetSecret() string {
	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, this.un())
	return strings.ToUpper(this.base32encode(this.hmacSha1(buf.Bytes(), nil)))
}

// 获取动态码
func (this *GoogleAuth) GetCode(secret string) (string, error) {
	secretUpper := strings.ToUpper(secret)
	secretKey, err := this.base32decode(secretUpper)
	if err != nil {
		return "", err
	}
	number := this.oneTimePassword(secretKey, this.toBytes(firstTime.Unix()/30))
	return fmt.Sprintf("%06d", number), nil

}

// 获取动态码二维码内容
func (this *GoogleAuth) GetQrcode(user, secret string) string {
	return fmt.Sprintf("otpauth://totp/%s?secret=%s", user, secret)
}

// 验证动态码
func (this *GoogleAuth) VerifyCode(secret, code string) (bool, error) {
	_code, err := this.GetCode(secret)
	fmt.Println(_code, code)
	if err != nil {
		return false, err
	}
	return _code == code, nil
}

var err error

type ntp_struct struct {
	FirstByte, A, B, C uint8
	D, E, F            uint32
	G, H               uint64
	ReceiveTime        uint64
	J                  uint64
}

var addrs = []string{
	"ntp.aliyun.com:123",
	"cn.ntp.org.cn:123",
	"time.asia.apple.com:123",
	"ntp.neu.edu.cn:123",
	"time1.cloud.tencent.com:123",
	"ntp1.aliyun.com:123",
	"time3.cloud.tencent.com:123",
	"ntp4.aliyun.com:123",
}

func getNTPTime(addr string) (time.Time,error) {
	// "ntp1.aliyun.com:123" "cn.ntp.org.cn:123"
	sock, _ := net.Dial("udp", addr)
	if sock == nil {
		return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),err
	}
	_ = sock.SetDeadline(time.Now().Add(2 * time.Second))
	defer func() { _ = sock.Close() }()
	ntp_transmit := new(ntp_struct)
	ntp_transmit.FirstByte = 0x1b

	_ = binary.Write(sock, binary.BigEndian, ntp_transmit)
	_ = binary.Read(sock, binary.BigEndian, ntp_transmit)
	return time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration((ntp_transmit.ReceiveTime >> 32) * 1000000000)),nil
}


func getotp() string {
	for _,i := range addrs{
		firstTime,err = getNTPTime(i)
		if err == nil{
			break
		}
	}

	// secret最好持久化保存在
	// 验证,动态码(从谷歌验证器获取或者freeotp获取)
	code,_ := NewGoogleAuth().GetCode(string(secret))

	return code
}

