# 🌟 LFI Parameter Finder 🌟

Welcome to the **LFI Parameter Finder**! This tool is designed to scan URLs for potential Local File Inclusion (LFI) vulnerabilities.

## ⚙️ Features

- 🚀 Test multiple URLs for LFI vulnerabilities
- 🧪 Use default or custom payloads for testing
- 🌐 Crawl URLs to find internal links
- 📝 Save results automatically to an output file

## 📦 Requirements


 ```bash
git clone https://github.com/Hackpy3/lfi_finder
cd lfi_finder
 ```
```bash
pip install -r requirements.txt
```
   ```bash
   go install github.com/tomnomnom/waybackurls@latest
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



