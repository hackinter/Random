import requests
from bs4 import BeautifulSoup
import re
import threading
import time
from urllib.parse import urljoin
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

# থ্রেড সংখ্যা
THREADS = 10
console = Console()

def fetch_html(url):
    """ ওয়েবসাইট থেকে HTML ফেচ করবে """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException:
        return None

def find_php_parameters(url, results):
    """ PHP প্যারামিটার খুঁজে বের করবে """
    html_content = fetch_html(url)
    if not html_content:
        return

    soup = BeautifulSoup(html_content, 'html.parser')
    links = soup.find_all('a', href=True)

    php_param_pattern = re.compile(r'\?(\w+)=([^&]*)')
    
    for link in links:
        href = link['href']
        full_url = urljoin(url, href)
        
        if php_param_pattern.search(href):
            results.append(full_url)

def check_live(url):
    """ URL লাইভ আছে কিনা চেক করবে """
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        return response.status_code in [200, 301, 302]
    except requests.RequestException:
        return False

def multi_thread_scan(url):
    """ মাল্টি-থ্রেড স্ক্যান চালাবে """
    results = []
    threads = []
    
    for _ in range(THREADS):
        thread = threading.Thread(target=find_php_parameters, args=(url, results))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # ডুপ্লিকেট রিমুভ করা
    results = list(set(results))
    
    # লাইভ চেক
    live_results = [link for link in results if check_live(link)]
    
    return live_results

if __name__ == "__main__":
    target_url = input("Enter target URL: ").strip()
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    console.print("\n[bold cyan]⚡️ Generating Website Analysis... Please wait...[/bold cyan]")
    
    with Progress() as progress:
        task = progress.add_task("[bold magenta]Loading...", total=100)
        for _ in range(100):
            time.sleep(0.01)
            progress.update(task, advance=1)
    
    console.print("\n🔍 Scanning for PHP parameters...\n", style="yellow")
    found_links = multi_thread_scan(target_url)

    if found_links:
        table = Table(title="Live PHP Parameters")
        table.add_column("Index", justify="center", style="cyan", no_wrap=True)
        table.add_column("URL", style="magenta")
        
        for idx, link in enumerate(found_links, 1):
            table.add_row(str(idx), link)
        
        console.print(table)
    else:
        console.print("❌ No live PHP parameters found.", style="red")
