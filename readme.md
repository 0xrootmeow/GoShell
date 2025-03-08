# Go Reverse Shell with Evasion Techniques

This Go program implements a reverse shell with several anti-detection and anti-debugging techniques, designed for educational purposes and authorized penetration testing. **Use with caution and only in environments where you have explicit permission.**

**Disclaimer:** This code is provided for educational purposes only. Unauthorized use is strictly prohibited. The author is not responsible for any misuse.

## Features

* **Encrypted Communication:**
    * Uses AES-256 encryption with a randomly generated Initialization Vector (IV) for each session to encrypt the communication between the attacker and the target.
    * The target host and port are also encrypted, making static analysis more difficult.
* **String Obfuscation:**
    * Dynamically obfuscates critical strings (e.g., "powershell.exe", "/bin/sh") at runtime to evade signature-based detection.
* **Debugger Detection:**
    * Checks for the presence of a debugger using the `IsDebuggerPresent` API on Windows, exiting if one is detected.
* **Cross-Platform Compatibility:**
    * Works on both Windows and Linux systems, automatically selecting the appropriate shell.
* **Time Delays:**
    * Includes a time delay in the `init` function to potentially evade timing-based detection.
* **Base64 Encoding:**
    * Uses base64 encoding to hide the encrypted host and port.
* **Minimization of direct syscalls:**
    * attempts to minimize the amount of direct syscalls.

## Usage

1.  **Generate Encrypted Host/Port and Key:**
    * Run the Go program. It will print the encrypted host/port string and the base64-encoded key.
    * Copy these values.
2.  **Update the Code:**
    * Replace the placeholder `encryptedHostPort` and `key` values in the `main.go` file with the generated strings.
3.  **Compile:**
    * **Windows:** `go build -ldflags="-H windowsgui" main.go`
    * **Linux:** `go build main.go`
4.  **Set up a Listener:**
    * On your attacker machine, set up a netcat listener: `nc -lvp <port>`
5.  **Run the Executable:**
    * Execute the compiled binary on the target machine.

## Code Explanation

* **Encryption/Decryption:**
    * The `encrypt` and `decrypt` functions use AES-256 in CFB mode.
* **String Obfuscation:**
    * The `randomizeString` function randomizes the bytes of strings.
* **Debugger Detection:**
    * The `isDebuggerPresent` function uses the Windows API to detect debuggers.
* **Shell Selection:**
    * The `main` function dynamically selects the appropriate shell based on the operating system.
* **Init Function:**
    * The `init` function handles the encrypted host/port generation and debugger detection.

## Building for Windows

If you are building this on windows, you can use this command:

```bash
go build -ldflags="-H windowsgui" main.go
