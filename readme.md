# Python Web Vulnerability Scanner (GUI Application)

## Project Overview

This is a comprehensive web application vulnerability scanner developed in Python. Designed as a portfolio piece for cybersecurity, it combines robust backend scanning logic with an interactive and modern graphical user interface. It demonstrates core concepts of web interaction, intelligent crawling, and essential vulnerability detection.

## Features

This scanner currently includes the following capabilities:

* **Graphical User Interface (GUI):**
    * Built with **PyQt6**, offering a modern, visually appealing, and intuitive user experience.
    * Features custom styling via **Qt Style Sheets (QSS)** for an enhanced aesthetic.
    * Provides interactive input fields for Target URL and Max Depth.
    * Displays real-time scan progress and results in a dedicated, scrollable output area.
    * Ensures UI responsiveness during scans by running the core logic in a **separate thread**.
    * Includes a **"Stop Scan" button** for graceful termination of ongoing scans.
* **HTTP Interaction:** Handles various HTTP responses and network errors using the `requests` library.
* **Intelligent Web Spidering (Crawler):**
    * Implements a **Breadth-First Search (BFS)** algorithm for systematic website exploration.
    * Efficiently manages the crawl queue using Python's `collections.deque` and prevents redundant crawling with a `set` for visited URLs.
    * Supports **depth-controlled crawling** to limit the scan's scope.
    * Includes a polite `time.sleep()` delay between requests to avoid overwhelming target servers.
    * **Domain Filtering:** Ensures the crawler stays strictly within the specified target domain, ignoring external links.
    * **Parameterized URL Collection:** Identifies and collects URLs that contain query parameters (e.g., `?id=123`), recognizing them as common points for web vulnerabilities.
* **Basic Vulnerability Detection Modules:**
    * **Cross-Site Scripting (XSS) Scanner:** Tests for basic reflected XSS by injecting payloads into URL parameters and checking for unencoded reflection in the HTML response.
    * **SQL Injection (SQLi) Scanner:** Performs basic error-based SQLi checks on parameterized URLs by injecting SQL payloads and analyzing responses for common database error signatures.
    * **Sensitive File/Directory Exposure:** Attempts to discover commonly exposed sensitive files (e.g., `.env`, `phpinfo.php`, `admin/`, `robots.txt`, `sitemap.xml`) by appending predefined paths to base URLs and checking for 200 OK responses.

## Ethical Usage Statement

**This tool is developed for educational purposes, learning, and authorized security testing ONLY.**
**DO NOT use this scanner on any website or system without explicit, written permission from the owner.** Unauthorized scanning can lead to legal consequences and severe reputational damage. Always ensure you have proper authorization before initiating any security testing.

## Installation

To set up and run this scanner, follow these steps:

1.  **Clone the Repository (if applicable):**
    ```bash
    git clone [https://github.com/Tabbi109/WebVulnScanner.git](https://github.com/Tabbi109/WebVulnScanner.git)
    cd your-project-name
    ```
    (If you are using Git, otherwise just navigate to your `web_scanner` directory)

2.  **Create and Activate a Virtual Environment:**
    It's highly recommended to use a virtual environment to manage project dependencies.
    ```bash
    python -m venv .venv
    ```
    * **On macOS/Linux:**
        ```bash
        source .venv/bin/activate
        ```
    * **On Windows (Command Prompt):**
        ```cmd
        .venv\Scripts\activate.bat
        ```
    * **On Windows (PowerShell - as seen in your setup):**
        ```powershell
        .venv\Scripts\activate
        ```

3.  **Install Dependencies:**
    Once your virtual environment is active, install all required Python libraries listed in `requirements.txt`.
    ```bash
    pip install -r requirements.txt
    ```

## How to Run

After installation, you can run the scanner in two ways:

### 1. Run the GUI Application (Recommended)

This is the primary way to interact with the scanner, providing a user-friendly graphical interface.

```bash
python app_PyQt.py
