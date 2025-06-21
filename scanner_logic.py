# scanner_logic.py content:

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from collections import deque
from requests.exceptions import RequestException
import time
import threading 

# --- Helper function ---
def extract_links_from_page(url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/html' not in content_type:
            return set()

        soup = BeautifulSoup(response.text, 'html.parser')
        found_links = set()

        for a_tag in soup.find_all('a'):
            href = a_tag.get('href')
            if href:
                absolute_url = urljoin(url, href)
                parsed_url = urlparse(absolute_url)

                if parsed_url.scheme in ['http', 'https']:
                    clean_url_base = urljoin(parsed_url.scheme + '://' + parsed_url.netloc, parsed_url.path)
                    final_url = clean_url_base
                    if parsed_url.query:
                        final_url += '?' + parsed_url.query
                    found_links.add(final_url)
        return found_links

    except RequestException:
        return set()
    except Exception:
        return set()

# --- XSS Check Function ---
def check_xss_vulnerability(url_with_param, payload="<script>alert('XSS')</script>"):
    parsed_url = urlparse(url_with_param)
    if not parsed_url.query:
        return False
    base_url = urljoin(parsed_url.scheme + '://' + parsed_url.netloc, parsed_url.path)
    query_params = parse_qs(parsed_url.query) 
    is_vulnerable = False
    for param_name in query_params:
        temp_params = query_params.copy()
        temp_params[param_name] = [payload]
        encoded_payload_query = urlencode(temp_params, quote_via=requests.utils.quote, safe='')
        test_url = f"{base_url}?{encoded_payload_query}"
        try:
            response = requests.get(test_url, timeout=5)
            response.raise_for_status()
            if payload in response.text:
                is_vulnerable = True
        except RequestException:
            pass
        except Exception:
            pass
    return is_vulnerable

# --- SQL Injection Check Function ---
def check_sqli_vulnerability(url_with_param):
    sqli_payloads = ["'", "\\", " OR 1=1--", "' OR '1'='1", " LIMIT 1 --"]
    db_error_signatures = ["sql syntax", "mysql error", "ora-", "syntax error", 
                           "unclosed quotation mark", "microsoft sql server", "odbc error"]
    parsed_url = urlparse(url_with_param)
    if not parsed_url.query:
        return False
    base_url = urljoin(parsed_url.scheme + '://' + parsed_url.netloc, parsed_url.path)
    query_params = parse_qs(parsed_url.query)
    is_vulnerable = False
    for param_name in query_params:
        for payload in sqli_payloads:
            temp_params = query_params.copy()
            temp_params[param_name] = [payload]
            encoded_payload_query = urlencode(temp_params, quote_via=requests.utils.quote, safe='')
            test_url = f"{base_url}?{encoded_payload_query}"
            try:
                response = requests.get(test_url, timeout=5)
                response.raise_for_status()
                response_text_lower = response.text.lower()
                for signature in db_error_signatures:
                    if signature in response_text_lower:
                        is_vulnerable = True
                        break 
            except RequestException:
                pass
            except Exception:
                pass
    return is_vulnerable

# --- Sensitive File/Directory Exposure Check Function ---
def check_sensitive_files_vulnerability(base_url):
    sensitive_paths = [
        ".git/config", ".env", "phpinfo.php", "info.php", 
        "test.php", "test.asp", "backup.zip", "backup.tar.gz", 
        "admin/", "robots.txt", "sitemap.xml", "wp-config.php.bak",    
        "/.well-known/security.txt", "WEB-INF/web.xml"
    ]
    vulnerable_files_found = set()
    for path in sensitive_paths:
        test_url = urljoin(base_url, path)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                vulnerable_files_found.add(test_url)
        except RequestException:
            pass
        except Exception:
            pass
    return vulnerable_files_found

# --- Main Spider & Scanner Function ---
def crawl_and_scan(start_url, max_depth=1, progress_callback=None, stop_event=None): 
    """
    Performs a web spidering/crawling operation using BFS,
    with domain filtering, collection of parameterized URLs, and basic XSS/SQLi/Sensitive File scanning.
    Includes a progress_callback for GUI updates and a stop_event for graceful termination.
    """
    base_netloc = urlparse(start_url).netloc
    if not base_netloc:
        if progress_callback:
            progress_callback.update_text(f"Error: Invalid start_url '{start_url}' - cannot determine base domain.") # Changed to .update_text()
        return [], [], [], [], []

    to_crawl = deque([(start_url, 0)])
    crawled_urls = set()
    parameterized_urls = set()
    xss_vulnerable_urls = set()
    sqli_vulnerable_urls = set()
    sensitive_files_vulnerable_urls = set()
    
    if progress_callback:
        progress_callback.update_text(f"Starting crawl and scan from: {start_url} (Max Depth: {max_depth}, Base Domain: {base_netloc})") # Changed to .update_text()
        progress_callback.update_text("-" * 70) # Changed to .update_text()

    while to_crawl:
        # Check if stop_event is set at the beginning of each major loop iteration
        if stop_event and stop_event.is_set():
            break # Exit the while loop gracefully

        current_url, current_depth = to_crawl.popleft()

        if current_url in crawled_urls:
            continue
        if current_depth > max_depth:
            continue
        current_netloc = urlparse(current_url).netloc
        if current_netloc != base_netloc:
            continue

        if progress_callback:
            progress_callback.update_text(f"  Crawling (Depth {current_depth}): {current_url}") # Changed to .update_text()
        crawled_urls.add(current_url)

        # Add a stop check before making external requests or long operations
        if stop_event and stop_event.is_set():
            break # Exit the while loop

        current_base_url_no_params = urljoin(urlparse(current_url).scheme + '://' + urlparse(current_url).netloc, urlparse(current_url).path)

        if current_base_url_no_params not in sensitive_files_vulnerable_urls:
            new_vulnerabilities = check_sensitive_files_vulnerability(current_base_url_no_params)
            if new_vulnerabilities and progress_callback:
                for vuln_url in new_vulnerabilities:
                    progress_callback.update_text(f"      [!!!] Possible Sensitive File/Directory Found! {vuln_url} responded with 200 OK.") # Changed to .update_text()
            sensitive_files_vulnerable_urls.update(new_vulnerabilities)

        if urlparse(current_url).query:
            parameterized_urls.add(current_url)
            
            # Add stop check before XSS/SQLi tests (as these can be many requests)
            if stop_event and stop_event.is_set():
                break # Exit the while loop

            if check_xss_vulnerability(current_url):
                xss_vulnerable_urls.add(current_url)
                if progress_callback:
                    progress_callback.update_text(f"      [!!!] XSS - {current_url} (Payload reflected)") # Changed to .update_text()

            # Add stop check between XSS and SQLi
            if stop_event and stop_event.is_set():
                break # Exit the while loop

            if check_sqli_vulnerability(current_url):
                sqli_vulnerable_urls.add(current_url)
                if progress_callback:
                    progress_callback.update_text(f"      [!!!] SQLi - {current_url} (Error signature detected)") # Changed to .update_text()

        # Add a stop check after processing current URL's vulnerabilities but before links
        if stop_event and stop_event.is_set():
            break # Exit the while loop

        time.sleep(0.5)

        links_on_page = extract_links_from_page(current_url)

        for link in links_on_page:
            if link not in crawled_urls:
                link_netloc = urlparse(link).netloc
                if link_netloc == base_netloc:
                    to_crawl.append((link, current_depth + 1))
            
            # Add stop check after processing all links from a page
            if stop_event and stop_event.is_set():
                break

    # Only print final summary if scan was NOT stopped (preventing duplicate "Scan finished" messages)
    if not (stop_event and stop_event.is_set()):
        if progress_callback:
            progress_callback.update_text("-" * 70) # Changed to .update_text()
            progress_callback.update_text(f"Crawl and scan finished for {start_url}.") # Changed to .update_text()
            progress_callback.update_text(f"Total unique URLs crawled (within domain): {len(crawled_urls)}") # Changed to .update_text()
            progress_callback.update_text(f"Total unique parameterized URLs found (within domain): {len(parameterized_urls)}") # Changed to .update_text()
            progress_callback.update_text(f"Total unique URLs potentially XSS vulnerable: {len(xss_vulnerable_urls)}") # Changed to .update_text()
            progress_callback.update_text(f"Total unique URLs potentially SQL Injection vulnerable: {len(sqli_vulnerable_urls)}") # Changed to .update_text()
            progress_callback.update_text(f"Total unique URLs potentially Sensitive File/Directory vulnerable: {len(sensitive_files_vulnerable_urls)}") # Changed to .update_text()

            progress_callback.update_text("\n--- Crawled URLs (within domain): ---") # Changed to .update_text()
            if crawled_urls:
                for url in sorted(list(crawled_urls)):
                    progress_callback.update_text(f"  - {url}") # Changed to .update_text()
            else:
                progress_callback.update_text("  No URLs crawled within the specified depth and domain.") # Changed to .update_text()

            progress_callback.update_text("\n--- Parameterized URLs Found (within domain): ---") # Changed to .update_text()
            if parameterized_urls:
                for url in sorted(list(parameterized_urls)):
                    progress_callback.update_text(f"  - {url}") # Changed to .update_text()
            else:
                progress_callback.update_text("  No parameterized URLs found within the specified depth and domain.") # Changed to .update_text()
            
            progress_callback.update_text("\nPotentially XSS Vulnerable URLs Found:") # Changed to .update_text()
            if xss_vulnerable_urls:
                for url in sorted(list(xss_vulnerable_urls)):
                    progress_callback.update_text(f"  [!!!] XSS - {url}") # Changed to .update_text()
            else:
                progress_callback.update_text("  No XSS vulnerabilities detected with the basic check.") # Changed to .update_text()

            progress_callback.update_text("\nPotentially SQL Injection Vulnerable URLs Found:") # Changed to .update_text()
            if sqli_vulnerable_urls:
                for url in sorted(list(sqli_vulnerable_urls)):
                    progress_callback.update_text(f"  [!!!] SQLi - {url}") # Changed to .update_text()
            else:
                progress_callback.update_text("  No SQL Injection vulnerabilities detected with the basic check.") # Changed to .update_text()

            progress_callback.update_text("\nPotentially Sensitive File/Directory Vulnerable URLs Found:") # Changed to .update_text()
            if sensitive_files_vulnerable_urls:
                for url in sorted(list(sensitive_files_vulnerable_urls)):
                    progress_callback.update_text(f"  [!!!] Sensitive File - {url}") # Changed to .update_text()
            else:
                progress_callback.update_text("  No Sensitive File/Directory vulnerabilities detected with the basic check.") # Changed to .update_text()
        
    return list(crawled_urls), list(parameterized_urls), list(xss_vulnerable_urls), list(sqli_vulnerable_urls), list(sensitive_files_vulnerable_urls)