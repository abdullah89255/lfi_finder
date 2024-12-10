# 🌟 LFI Parameter Finder 🌟

Welcome to the **LFI Parameter Finder**! This tool is designed to scan URLs for potential Local File Inclusion (LFI) vulnerabilities.

## ⚙️ Features

- 🚀 Test multiple URLs for LFI vulnerabilities
- 🧪 Use default or custom payloads for testing
- 🌐 Crawl URLs to find internal links
- 📝 Save results automatically to an output file

## 📂 Default LFI Payloads

The tool comes with a comprehensive set of default LFI payloads to test various sensitive files in Linux/Unix systems:

```
/etc/passwd, /etc/shadow, /var/log/auth.log, /windows/win.ini, /windows/system32/drivers/etc/hosts, /usr/local/apache2/logs/error_log, /proc/self/environ, /etc/issue, /opt/lampp/logs/access_log, /etc/group, /etc/hosts, /etc/motd, /etc/shells, /etc/network/interfaces, /etc/crontab, /etc/apt/sources.list, /etc/hostname, /etc/resolv.conf, /etc/mail.rc, /etc/postfix/main.cf, /etc/aliases, /etc/exports, /etc/fstab, /etc/inittab, /etc/ld.so.conf, /etc/logrotate.conf, /etc/mtab, /etc/nsswitch.conf, /opt/samba/smb.conf, /etc/profile, /etc/protocols, /etc/securetty, /etc/services, /etc/sysctl.conf, /etc/systemd/system.conf, /etc/timezone, /etc/vsftpd.conf, /usr/lib/python3/dist-packages/apt_pkg.so, /usr/share/common-licenses/GPL, /var/log/alternatives.log, /var/log/apport.log, /var/log/apt/history.log, /var/log/apt/term.log, /var/log/auth.log, /var/log/boot.log, /var/log/dpkg.log, /var/log/faillog, /var/log/kern.log, /var/log/lastlog, /var/log/syslog, /var/log/wtmp, /var/log/xferlog, /var/www/html/index.html, /proc/self/cmdline, /proc/self/status, /proc/version, /proc/net/arp, /proc/net/fib_trie, /proc/net/tcp, /proc/net/udp, /proc/net/unix, /proc/net/route, /proc/net/rt_cache, /proc/self/mounts, /var/run/utmp, /var/run/docker.sock.
```

## 📦 Requirements

Ensure you have the necessary libraries installed. You can install them using the following command:
```bash
pip install -r requirements.txt
```
 ```bash
git clone https://github.com/Hackpy3/lfi_finder
cd lfi-finder
 ```
## 📝 Usage

1. **Run the Script**:
    ```bash
    python lfi_finder.py
    ```

2. **Load URLs from File**: Choose whether to load URLs from a `.txt` file. If 'yes', provide the file path.

3. **Input URL**: Enter the target URL if not loading from a file.

4. **Output File**: Enter the name for the output file.

5. **Payloads from File**: Choose whether to load payloads from a `.txt` file. If 'yes', provide the file path.

## 🚀 Example

To scan a list of URLs for LFI vulnerabilities, you can create a file `urls.txt` with your target URLs and run the script:
### Example 1: Scanning a Single URL
```bash
python lfi_finder.py
# Follow the prompts:
# Enter 'n' when asked to load URLs from a file
# Enter the target URL (e.g., https://example.com)
# Enter the name for the output file (e.g., results.txt)
# Enter 'n' when asked to load payloads from a file
```

### Example 2: Scanning Multiple URLs from a File
Create a file `urls.txt` with the URLs to be scanned:
```
https://example1.com
https://example2.com
```
Run the script:
```bash
python lfi_finder.py
# Follow the prompts:
# Enter 'y' when asked to load URLs from a file
# Provide the file path (e.g., /path/to/urls.txt)
# Enter the name for the output file (e.g., results.txt)
# Enter 'n' when asked to load payloads from a file
```

### Example 3: Using Custom Payloads from a File
Create a file `payloads.txt` with custom payloads:
```
../../../../../../../../etc/passwd
../../../../../../../../etc/shadow
```
Run the script:
```bash
python lfi_finder.py
# Follow the prompts:
# Enter 'n' when asked to load URLs from a file
# Enter the target URL (e.g., https://example.com)
# Enter the name for the output file (e.g., results.txt)
# Enter 'y' when asked to load payloads from a file
# Provide the file path (e.g., /path/to/payloads.txt)
```

Follow the prompts to load URLs, specify an output file, and load payloads if needed.

## ⚠️ Disclaimer

Use this tool only for educational purposes and authorized testing. Unauthorized use of this tool to target websites without permission is illegal.

## 📂 License

This project is licensed under the MIT License.

## ✨ Contributions

Feel free to contribute by opening an issue or submitting a pull request.



Happy hunting! 🕵️🔍



