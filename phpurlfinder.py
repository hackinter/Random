import requests
from bs4 import BeautifulSoup
import re
import threading
from urllib.parse import urljoin

# থ্রেড সংখ্যা (স্পিড বাড়ানোর জন্য)
THREADS = 10

def fetch_html(url):
    """ ওয়েবসাইট থেকে HTML ফেচ করবে """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None

def find_php_id_links(url, results):
    """ php?id=?? লিংক খুঁজে বের করবে """
    html_content = fetch_html(url)
    if not html_content:
        return

    soup = BeautifulSoup(html_content, 'html.parser')
    links = soup.find_all('a', href=True)

    php_id_pattern = re.compile(r'php\?id=(\d+)')
    for link in links:
        href = link['href']
        full_url = urljoin(url, href)
        if php_id_pattern.search(href):
            results.append(full_url)

def multi_thread_scan(url):
    """ স্পিড বাড়ানোর জন্য মাল্টি-থ্রেড স্ক্যান চালাবে """
    results = []
    threads = []
    
    for _ in range(THREADS):
        thread = threading.Thread(target=find_php_id_links, args=(url, results))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()

    return results

if __name__ == "__main__":
    target_url = input("Enter target URL: ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    print("\n🔍 Scanning for php?id=?? links...\n")
    found_links = multi_thread_scan(target_url)

    if found_links:
        print("\n✅ Found PHP ID Parameters:")
        for idx, link in enumerate(found_links, 1):
            print(f"[{idx}] {link}")
    else:
        print("❌ No matching php?id=?? parameters found.")
