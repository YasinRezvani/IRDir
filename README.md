# IRDir - Iranian Directory Enumerator

**A specialized directory and path enumeration tool optimized for Iranian (.ir) domains and Persian websites.**
<img width="1536" height="1024" alt="banner" src="https://github.com/user-attachments/assets/fdf5d793-32ec-4cc9-93e5-9953d78bedd0" />

## Description

IRDir is an open-source security tool designed for directory and path enumeration, similar to popular tools like Gobuster and Dirbuster. It is specifically tailored for Iranian web infrastructure, focusing on .ir domains and Persian-language websites. The tool incorporates a custom Iranian wordlist derived from extensive crawling of Iranian sites and AI-generated content, combined with selected wordlists from the SecLists repository.

This makes IRDir particularly effective for penetration testers and security researchers targeting Iranian web servers, where standard wordlists may fall short due to unique directory structures, file naming conventions in Persian, and culturally specific paths.

Key highlights:
- **Optimized for Iranian Domains**: Handles Persian characters, URL-encoded inputs, and common patterns found in Iranian web applications.
- **Comprehensive Coverage**: Merges multiple wordlists to provide approximately 390,000 unique paths and files.
- **User-Friendly Interface**: Includes a GUI for easy configuration and real-time results monitoring.
- **Ethical Use**: Intended for authorized security testing and research only.

## Features

- **Multi-Threaded Scanning**: Supports configurable concurrency for faster enumeration (default: 35 threads).
- **Custom Delay and Timeout**: Adjustable request delays (default: 0.1s) and timeouts (default: 10s) to avoid detection.
- **Wordlist Management**: Automatically loads, merges, and deduplicates wordlists from the `wordlists/` directory.
- **Filtering Options**: Filter results by HTTP status codes, response size, and keywords.
- **Export Capabilities**: Export results to CSV or JSON for further analysis.
- **Detailed Logging**: Real-time logs and progress tracking.
- **GUI Enhancements**: Modern interface with live results table, details viewer, and browser integration.
- **Cross-Platform**: Runs on Windows via pre-built executable or from Python source on any platform.

## Quick Demo

The video below demonstrates IRDir's complete workflow for enumerating directories on an Iranian (.ir) domain:

## Installation

IRDir can be installed via a pre-built executable for Windows or by running from source.

### Method 1: Pre-built Executable (Windows)

1. Download the `.exe` file.
2. Run the executable directly—no additional dependencies required.

### Method 2: From Source

1. Clone the repository:
   ```
   git clone https://github.com/YasinRezvani/IRDir.git
   cd irdir
   ```

2. Install Python dependencies (requires Python 3.8+):
   ```
   pip install requests
   ```

3. Run the tool:
   ```
   python IRDir.py
   ```

Note: Ensure the `wordlists/` directory is populated with the provided wordlists. If missing, download them from the repository.

## Usage

Launch IRDir via the executable or Python script. The GUI will open automatically.

1. **Configure the Scan**:
   - Enter the target URL (e.g., `https://iran.ir`).
   - Adjust concurrency, delay, and timeout as needed.
   - Select wordlists from the available options (all selected by default).

2. **Start the Scan**:
   - Click "Start Scan".
   - Monitor progress in the live results table.

3. **Filter and Export**:
   - Use filters for status codes (e.g., 200, 403), size, or keywords.
   - Export results via the "Export All CSV/JSON" buttons.

## Wordlist Information

IRDir includes a robust set of wordlists, with a focus on Iranian-specific content. All wordlists are stored in the `wordlists/` directory and are automatically merged and deduplicated during scans.

### Iranian-Specific Wordlists

- **irdir-iranian-common.txt** (25,000+ entries):
  - Curated from crawling thousands of Iranian websites.
  - Includes common Persian directory names, file paths, admin panels, and culturally relevant terms.
  - Augmented with AI-generated content to cover variations and edge cases.

- **irdir-iranian-common-encoded.txt**:
  - URL-encoded version of the above, ideal for servers that handle encoded inputs differently.

These wordlists address gaps in standard tools by including Persian script, Farsi transliterations, and Iran-specific web patterns.

### Included SecLists Wordlists (38 Files)

IRDir bundles 38 wordlists from the [SecLists repository](https://github.com/danielmiessler/SecLists) for broad coverage:

- dirb-common.txt
- dirb-extensions_common.txt
- dirbuster-directory-list-2.3-medium.txt
- dirsearch-dicc.txt
- raft-medium-directories.txt
- raft-medium-files.txt
- seclists-Apache-Tomcat.txt
- seclists-Apache.txt
- seclists-cms-configuration-files.txt
- seclists-Common-PHP-Filenames.txt
- seclists-common.txt
- seclists-Django.txt
- seclists-dotnetnuke.txt
- seclists-dsstorewordlist.txt
- seclists-graphql.txt
- seclists-IIS.txt
- seclists-Java-Spring-Boot.txt
- seclists-joomla.txt
- seclists-laravel.txt
- seclists-nginx.txt
- seclists-opencart.txt
- seclists-PHP.fuzz.txt
- seclists-phpbb.txt
- seclists-quickhits.txt
- seclists-reverse-proxy-inconsistencies.txt
- seclists-tomcat.txt
- seclists-urls-joomla-3.0.3.txt
- seclists-urls-wordpress-3.3.1.txt
- seclists-versioning_metafiles.txt
- seclists-vulnerability-scan_j2ee-websites_WEB-INF.txt
- seclists-web-extensions.txt
- seclists-wordpress.fuzz.txt
- seclists-wp-plugins.fuzz.txt
- seclists-wp-themes.fuzz.txt
- wfuzz-admin-panels.txt
- wfuzz-common.txt
- wfuzz-extensions_common.txt
- wfuzz-medium.txt

**Total Unique Entries**: Approximately 390,000 after merging and deduplication.

Users can add custom wordlists to the `wordlists/` directory for automatic inclusion.

## Configuration Options

- **Target Domain**: Base URL for enumeration (supports HTTPS/HTTP).
- **Concurrency**: Number of simultaneous requests (1-100, default 35).
- **Delay**: Time between requests in seconds (default 0.1).
- **Timeout**: Request timeout in seconds (default 10).
- **Status Filters**: Toggle HTTP codes (200, 301, etc.) for display.
- **Size Filters**: Min/max response size in bytes.
- **Keyword Filter**: Search within paths, URLs, notes, or snippets.

Configurations are set via the GUI; future versions may include CLI flags.

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/YourFeature`).
3. Commit changes (`git commit -m 'Add YourFeature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a Pull Request.

Focus on improvements like new wordlists, bug fixes, or performance enhancements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the [SecLists](https://github.com/danielmiessler/SecLists) project for providing high-quality wordlists.
- Inspired by tools like Gobuster and Dirbuster.
- Iranian wordlist data sourced from ethical crawling and AI tools (e.g., Grok AI for generation).

## Disclaimer

IRDir is intended for educational purposes and authorized security testing only. Unauthorized use for scanning or enumerating websites without permission may violate laws and terms of service. The developers assume no liability for misuse. Always obtain explicit permission before testing any system.
