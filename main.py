import requests
import pandas as pd
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import logging
import time
import random
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import deque
import os
from playwright.sync_api import sync_playwright

# Ignorowanie ostrzeżeń o niezaufanych certyfikatach SSL
import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    'Mozilla/5.0 (Android 10; Mobile; rv:79.0) Gecko/79.0 Firefox/79.0'
]

email_pattern = re.compile(
    r'[\w\.-]+@[\w\.-]+\.\w+',
    re.UNICODE
)

write_lock = Lock()

def reverse_email(encoded_email):
    """
    Dekoduje e-mail zapisany w odwrotnej kolejności.
    """
    return encoded_email[::-1]

def decode_js_escaped_string(escaped_str):
    """
    Dekoduje ciąg znaków zakodowany w sekwencjach Unicode JavaScript.
    """
    try:
        decoded = bytes(escaped_str, "utf-8").decode("unicode_escape")
        return decoded
    except Exception as e:
        logging.error(f"Error decoding JavaScript escaped string: {e}")
        return escaped_str

def extract_emails(soup):
    """
    Wyszukuje e-maile w treści strony, uwzględniając różne metody ukrywania.
    """
    emails = set()

    # 1. E-maile w widocznym tekście
    text = soup.get_text(separator=' ', strip=True)
    emails_in_text = email_pattern.findall(text)
    emails.update(emails_in_text)

    # 2. E-maile w linkach mailto:
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('mailto:'):
            email = href[7:].split('?')[0]  # Usuń 'mailto:' i dodatkowe parametry
            emails.add(email)
        # 3. E-maile w linkach JavaScript z zakodowanymi sekwencjami Unicode
        elif href.startswith("javascript:"):
            if 'mailto:' in href:
                match = re.search(r"mailto:\s*'([^']+)'", href)
                if match:
                    encoded_email = match.group(1)
                    decoded_email = decode_js_escaped_string(encoded_email)
                    emails.add(decoded_email)
                else:
                    unicode_sequences = re.findall(r'\\u[0-9a-fA-F]{4}', href)
                    if unicode_sequences:
                        unicode_str = ''.join(unicode_sequences)
                        decoded_email = decode_js_escaped_string(unicode_str)
                        emails.add(decoded_email)

    # 4. E-maile w <span class="reverse">
    for span in soup.find_all('span', class_='reverse'):
        reversed_email = span.get_text()
        email = reverse_email(reversed_email)
        emails.add(email)

    # 5. E-maile w kodzie JavaScript
    for script in soup.find_all('script'):
        if script.string:
            script_text = script.string
            emails_in_script = email_pattern.findall(script_text)
            emails.update(emails_in_script)

    # 6. E-maile w atrybutach danych
    for attr in ['data-contact-email', 'data-email']:
        for tag in soup.find_all(attrs={attr: True}):
            email = tag.get(attr)
            emails.add(email)

    # Usuwanie duplikatów i pustych wartości
    emails = {email.strip() for email in emails if email and is_valid_email(email.strip())}

    return emails

def is_valid_email(email):
    """
    Sprawdza, czy e-mail jest poprawny.
    """
    invalid_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp']
    if any(email.lower().endswith(ext) for ext in invalid_extensions):
        return False
    if not email_pattern.fullmatch(email.strip()):
        return False
    return True

def create_session():
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "GET"],
        backoff_factor=1
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
    return session

def save_results(domain, emails, reason, output_file):
    """
    Zapisuje wyniki do pliku CSV.
    """
    with write_lock:
        header_needed = not os.path.exists(output_file)
        if emails:
            results = [{'Domena': domain, 'Email': email, 'Powód': ''} for email in emails]
        else:
            results = [{'Domena': domain, 'Email': 'X', 'Powód': reason}]
        df = pd.DataFrame(results)
        df.to_csv(output_file, index=False, mode='a', header=header_needed)

def detect_js_dependency(html):
    """
    Wykrywa, czy strona wymaga renderowania JavaScript.
    """
    keywords = ['<noscript>', 'ReactDOM.render', 'Vue.component', 'angular.module', 'application/javascript', 'text/javascript', 'window.', 'document.']
    return any(keyword in html for keyword in keywords)

def fetch_with_js_rendering(url):
    """
    Pobiera zawartość strony z renderowaniem JavaScript za pomocą Playwright.
    """
    html = ''
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            page.goto(url, timeout=30000)
            page.wait_for_load_state('networkidle', timeout=10000)
            html = page.content()
            browser.close()
    except Exception as e:
        logging.error(f"Error rendering JavaScript for URL: {url}, {e}")
    return html

def scrape_emails_from_url(url, session):
    """
    Pobiera e-maile z URL i analizuje zawartość.
    """
    emails = set()
    reason = ""
    try:
        response = session.get(url, timeout=10, verify=False)
        response.raise_for_status()
        html = response.text

        if detect_js_dependency(html):
            logging.info(f"JavaScript detected on {url}. Rendering...")
            html = fetch_with_js_rendering(url)

        soup = BeautifulSoup(html, 'html.parser')

        emails_in_page = extract_emails(soup)
        emails.update(emails_in_page)

        if not emails:
            if soup.find('form'):
                reason = "Brak e-maila, formularz kontaktowy"
            else:
                reason = "Brak e-maila na stronie"

    except requests.RequestException as e:
        reason = "Błąd ładowania strony"
        logging.error(f"Error fetching URL: {url}, {e}")
    except Exception as e:
        reason = "Błąd podczas przetwarzania strony"
        logging.error(f"Error processing URL: {url}, {e}")
    return emails, reason

def crawl_domain(domain, session, max_pages=15, delay=5):
    """
    Przeszukuje domenę i zbiera e-maile.
    """
    visited_urls = set()
    urls_to_visit = deque([f"http://{domain}", f"https://{domain}"])
    all_emails = set()
    reason = "Nie znaleziono e-maila"

    while urls_to_visit and len(visited_urls) < max_pages:
        current_url = urls_to_visit.popleft()
        if current_url in visited_urls:
            continue
        visited_urls.add(current_url)
        logging.info(f"Processing URL: {current_url}")

        emails, page_reason = scrape_emails_from_url(current_url, session)
        all_emails.update(emails)

        if emails:
            reason = ""
            logging.info(f"Found emails at {current_url}: {emails}")
        else:
            if not reason:
                reason = page_reason

        if len(visited_urls) < max_pages:
            try:
                response = session.get(current_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    parsed_url = urlparse(full_url)
                    if parsed_url.netloc.endswith(domain) and full_url not in visited_urls:
                        if any(keyword in full_url.lower() for keyword in ['contact', 'kontakt', 'contacto']):
                            urls_to_visit.appendleft(full_url)
                        else:
                            urls_to_visit.append(full_url)
            except requests.RequestException as e:
                logging.error(f"Error processing URL: {current_url}, {e}")

        time.sleep(delay)

    return all_emails, reason

def scrape_emails_worker(domain, output_file, max_pages=1, delay=1):
    """
    Worker dla jednej domeny.
    """
    session = create_session()
    emails, reason = crawl_domain(domain, session, max_pages=max_pages, delay=delay)
    save_results(domain, emails, reason, output_file)

def main():
    input_file = 'input.xlsx'
    output_file = 'output_results.csv'

    logging.info(f"Loading input file: {input_file}")
    try:
        df_input = pd.read_excel(input_file)
        domains = df_input.iloc[:, 0].dropna().unique()
        logging.info(f"Found {len(domains)} domains to process.")
    except Exception as e:
        logging.error(f"Error reading input file: {e}")
        return

    # Usuń istniejący plik wynikowy
    if os.path.exists(output_file):
        os.remove(output_file)

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [
            executor.submit(scrape_emails_worker, domain, output_file, max_pages=5)
            for domain in domains
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Error in worker: {e}")

if __name__ == "__main__":
    main()
