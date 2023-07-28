package proxmox

import (
	"crypto/des"
	"crypto/tls"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"strings"
	"time"
)

var (
	bufCopy = NewBufCopy()
)

func (c *Client) VNCProxyWebsocketServeHTTP(path string, vnc *VNC, w http.ResponseWriter, r *http.Request, responseHeader http.Header) (err error) {
	upgrader := websocket.Upgrader{}
	websocketServe, err := upgrader.Upgrade(w, r, responseHeader)
	if err != nil {
		err = fmt.Errorf("upgrade http to websocket err: %+v", err)
		return
	}

	if strings.HasPrefix(path, "/") {
		path = strings.Replace(c.baseURL, "https://", "wss://", 1) + path
	}

	var tlsConfig *tls.Config
	transport := c.httpClient.Transport.(*http.Transport)
	if transport != nil {
		tlsConfig = transport.TLSClientConfig
	}
	c.log.Debugf("connecting to websocket: %s", path)
	dialer := &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 30 * time.Second,
		TLSClientConfig:  tlsConfig,
	}

	dialerHeaders := http.Header{}
	c.authHeaders(&dialerHeaders)

	pveVncConn, _, err := dialer.Dial(path, dialerHeaders)

	if err != nil {
		err = fmt.Errorf("connect to pve err: %+v", err)
		websocketServe.Close()
		return
	}

	defer func() {
		pveVncConn.Close()
		websocketServe.Close()
	}()

	var msgType int
	var msg []byte
	msgType, msg, err = pveVncConn.ReadMessage()
	if nil != err {
		err = fmt.Errorf("read pve rfb message err: %+v", err)
		return
	}
	//fmt.Println("pveVncConn1", msgType, msg, err, string(msg))
	//"RFB 003.008\n"
	if err = websocketServe.WriteMessage(msgType, msg); err != nil {
		err = fmt.Errorf("write websocket rfb message err: %+v", err)
		return
	}

	msgType, msg, err = websocketServe.ReadMessage()
	//fmt.Println("websocketServe2", msgType, msg, err, string(msg))
	if nil != err {
		err = fmt.Errorf("read websocket rfb message err: %+v", err)
		return
	}
	//"RFB 003.008\n"
	if err = pveVncConn.WriteMessage(msgType, msg); err != nil {
		err = fmt.Errorf("write pve rfb message err: %+v", err)
		return
	}
	msgType, msg, err = pveVncConn.ReadMessage()
	//fmt.Println("pveVncConn3", msgType, msg, err, string(msg))
	if nil != err {
		err = fmt.Errorf("read websocket auth type message err: %+v", err)
		return
	}
	//[]uint8{1,2}  type 2 is need password
	if err = pveVncConn.WriteMessage(websocket.BinaryMessage, []uint8{2}); err != nil {
		err = fmt.Errorf("write pve auth type message err: %+v", err)
		return
	}

	msgType, msg, err = pveVncConn.ReadMessage()
	//fmt.Println("pveVncConn4", msgType, msg, err, string(msg))
	if nil != err {
		err = fmt.Errorf("read pve auth random key message err: %+v", err)
		return
	}
	//[]unit8{...}  len 16
	enPassword, err := VNCAuthPasswordEncrypt(vnc.Ticket, msg)
	//fmt.Println("enPassword", enPassword, err, string(enPassword))
	if err = pveVncConn.WriteMessage(websocket.BinaryMessage, enPassword); err != nil {
		err = fmt.Errorf("write pve auth password message err: %+v", err)
		return
	}
	//msgType, msg, err = pveVncConn.ReadMessage()
	//fmt.Println("pveVncConn5", msgType, msg, err, string(msg))

	//send websocket do not need password
	if err = websocketServe.WriteMessage(websocket.BinaryMessage, []uint8{1, 1}); err != nil {
		err = fmt.Errorf("write websocket auth type message err: %+v", err)
		return
	}
	msgType, msg, err = websocketServe.ReadMessage()
	//fmt.Println("websocketServe6", msgType, msg, err, string(msg))
	if nil != err {
		err = fmt.Errorf("read websocket auth type return message err: %+v", err)
		return
	}

	go func() {

		for {
			_, err = bufCopy.Copy(websocketServe.UnderlyingConn(), pveVncConn.UnderlyingConn())
			if err != nil {
				err = fmt.Errorf("buf copy pve to websocket err: %+v", err)
				pveVncConn.Close()
				websocketServe.Close()
				return
			}
		}
	}()

	for {
		_, err = bufCopy.Copy(pveVncConn.UnderlyingConn(), websocketServe.UnderlyingConn())
		if err != nil {
			err = fmt.Errorf("buf copy websocket to pve err: %+v", err)
			pveVncConn.Close()
			websocketServe.Close()
			return
		}
	}

	return
}

func VNCAuthPasswordEncrypt(key string, bytes []byte) ([]byte, error) {
	keyBytes := []byte{0, 0, 0, 0, 0, 0, 0, 0}

	if len(key) > 8 {
		key = key[:8]
	}

	for i := 0; i < len(key); i++ {
		keyBytes[i] = reverseBits(key[i])
	}

	block, err := des.NewCipher(keyBytes)

	if err != nil {
		return nil, err
	}

	result1 := make([]byte, 8)
	block.Encrypt(result1, bytes)
	result2 := make([]byte, 8)
	block.Encrypt(result2, bytes[8:])

	crypted := append(result1, result2...)

	return crypted, nil
}

func reverseBits(b byte) byte {
	var reverse = [256]int{
		0, 128, 64, 192, 32, 160, 96, 224,
		16, 144, 80, 208, 48, 176, 112, 240,
		8, 136, 72, 200, 40, 168, 104, 232,
		24, 152, 88, 216, 56, 184, 120, 248,
		4, 132, 68, 196, 36, 164, 100, 228,
		20, 148, 84, 212, 52, 180, 116, 244,
		12, 140, 76, 204, 44, 172, 108, 236,
		28, 156, 92, 220, 60, 188, 124, 252,
		2, 130, 66, 194, 34, 162, 98, 226,
		18, 146, 82, 210, 50, 178, 114, 242,
		10, 138, 74, 202, 42, 170, 106, 234,
		26, 154, 90, 218, 58, 186, 122, 250,
		6, 134, 70, 198, 38, 166, 102, 230,
		22, 150, 86, 214, 54, 182, 118, 246,
		14, 142, 78, 206, 46, 174, 110, 238,
		30, 158, 94, 222, 62, 190, 126, 254,
		1, 129, 65, 193, 33, 161, 97, 225,
		17, 145, 81, 209, 49, 177, 113, 241,
		9, 137, 73, 201, 41, 169, 105, 233,
		25, 153, 89, 217, 57, 185, 121, 249,
		5, 133, 69, 197, 37, 165, 101, 229,
		21, 149, 85, 213, 53, 181, 117, 245,
		13, 141, 77, 205, 45, 173, 109, 237,
		29, 157, 93, 221, 61, 189, 125, 253,
		3, 131, 67, 195, 35, 163, 99, 227,
		19, 147, 83, 211, 51, 179, 115, 243,
		11, 139, 75, 203, 43, 171, 107, 235,
		27, 155, 91, 219, 59, 187, 123, 251,
		7, 135, 71, 199, 39, 167, 103, 231,
		23, 151, 87, 215, 55, 183, 119, 247,
		15, 143, 79, 207, 47, 175, 111, 239,
		31, 159, 95, 223, 63, 191, 127, 255,
	}

	return byte(reverse[int(b)])
}
