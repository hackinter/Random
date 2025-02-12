import requests
import socket
import json
import re
import whois
import dns.resolver
import ssl
from datetime import datetime
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.progress import track
import time

# Console Setup
console = Console()

# Headers Definition
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
}

def get_ip(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return "Unknown"

def get_whois_data(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    try:
        w = whois.whois(domain)
        return w.registrar if w.registrar else "Unknown"
    except:
        return "Unknown"

def get_dns_records(domain):
    records = {}
    try:
        records["A"] = [str(ip) for ip in dns.resolver.resolve(domain, 'A')]
    except:
        records["A"] = "Not Found"

    try:
        records["MX"] = [str(mx) for mx in dns.resolver.resolve(domain, 'MX')]
    except:
        records["MX"] = "Not Found"

    try:
        records["TXT"] = [str(txt) for txt in dns.resolver.resolve(domain, 'TXT')]
    except:
        records["TXT"] = "Not Found"

    return records

def check_ssl_certificate(url):
    domain = url.replace("https://", "").replace("http://", "").split("/")[0]
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    conn.connect((domain, 443))
    cert = conn.getpeercert()

    expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    days_remaining = (expiry_date - datetime.now()).days

    return {
        "Issuer": cert['issuer'][0][0][1],
        "Expiry Date": expiry_date.strftime('%Y-%m-%d'),
        "Days Remaining": days_remaining
    }

def enumerate_subdomains(domain):
    subdomains = []
    common_subdomains = ["www", "mail", "ftp", "admin", "test", "dev"]
    for sub in common_subdomains:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            subdomains.append(full_domain)
        except socket.gaierror:
            continue
    return subdomains

def check_robots_txt(url):
    robots_url = f"{url}/robots.txt"
    try:
        response = requests.get(robots_url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.text
        else:
            return "Not Found"
    except requests.exceptions.RequestException:
        return "Not Found"

def detect_social_media_links(soup):
    social_media_links = {
        "Facebook": "facebook.com",
        "Twitter": "twitter.com",
        "LinkedIn": "linkedin.com",
        "Instagram": "instagram.com",
        "YouTube": "youtube.com"
    }
    detected_links = {}
    for platform, domain in social_media_links.items():
        links = soup.find_all("a", href=re.compile(domain))
        if links:
            detected_links[platform] = [link.get("href") for link in links]
    return detected_links

def analyze_website(url):
    try:
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        source_code = response.text
        server_header = response.headers.get("Server", "Unknown")
        powered_by = response.headers.get("X-Powered-By", "Unknown")
        ip_address = get_ip(url)
        whois_info = get_whois_data(url)
        dns_records = get_dns_records(url.replace("https://", "").replace("http://", "").split("/")[0])

        # Table Setup
        table = Table(title=f"🌍 Website Analysis Report: {url}", style="cyan", show_lines=True)
        table.add_column("🔍 Feature", style="yellow", justify="left", no_wrap=True)
        table.add_column("🛠️ Detected", style="green", justify="left", no_wrap=True)

        # Basic Info
        if url:
            table.add_row("🌐 URL", url)
        if server_header != "Unknown":
            table.add_row("🖥️ Server", server_header)
        if powered_by != "Unknown":
            table.add_row("⚙️ Powered By", powered_by)
        if ip_address != "Unknown":
            table.add_row("📍 IP Address", ip_address)
        if whois_info != "Unknown":
            table.add_row("🔎 WHOIS Registrar", whois_info)

        # DNS Records
        if dns_records["A"] != "Not Found":
            table.add_row("📡 DNS A Record", ", ".join(dns_records["A"]))
        if dns_records["MX"] != "Not Found":
            table.add_row("📡 DNS MX Record", ", ".join(dns_records["MX"]))
        if dns_records["TXT"] != "Not Found":
            table.add_row("📡 DNS TXT Record", ", ".join(dns_records["TXT"]))

        # SSL/TLS Certificate
        ssl_info = check_ssl_certificate(url)
        table.add_row("🔒 SSL Issuer", ssl_info["Issuer"])
        table.add_row("🔒 SSL Expiry Date", ssl_info["Expiry Date"])
        table.add_row("🔒 SSL Days Remaining", str(ssl_info["Days Remaining"]))

        # Subdomains
        subdomains = enumerate_subdomains(url.replace("https://", "").replace("http://", "").split("/")[0])
        table.add_row("🌐 Subdomains", ", ".join(subdomains))

        # Robots.txt
        robots_txt = check_robots_txt(url)
        table.add_row("🤖 Robots.txt", robots_txt if robots_txt != "Not Found" else "Not Found")

        # Security Headers Detection
        security_headers = {
            "HSTS": "Strict-Transport-Security",
            "CSP": "Content-Security-Policy",
            "X-Frame-Options": "X-Frame-Options",
            "X-XSS-Protection": "X-XSS-Protection",
            "X-Content-Type-Options": "X-Content-Type-Options",
            "Referrer-Policy": "Referrer-Policy",
            "Permissions-Policy": "Permissions-Policy"
        }
        for sec_header, key in security_headers.items():
            if key in response.headers:
                table.add_row(f"🔐 {sec_header}", "Yes")

        # Programming Language Detection
        langs = {
            "PHP": "php",
            "Python": "flask|django",
            "Ruby": "rails",
            "Node.js": "express",
            "ASP.NET": "asp.net",
            "Java": "java",
            "Go": "go"
        }
        for lang, pattern in langs.items():
            if re.search(pattern, source_code, re.IGNORECASE):
                table.add_row(f"🛠️ {lang} Detected", "Yes")

        # CMS Detection
        cms_list = {
            "WordPress": "wp-content",
            "Joomla": "joomla",
            "Drupal": "drupal",
            "Magento": "magento",
            "Shopify": "cdn.shopify.com",
            "Ghost": "ghost.org",
            "Squarespace": "squarespace.com"
        }
        for cms, keyword in cms_list.items():
            if keyword in source_code.lower():
                table.add_row(f"✅ CMS: {cms}", "Yes")

        # JavaScript Libraries
        js_libraries = {
            "ReactJS": "react",
            "VueJS": "vue",
            "AngularJS": "angular",
            "jQuery": "jquery",
            "Bootstrap": "bootstrap",
            "Backbone.js": "backbone",
            "Ember.js": "ember"
        }
        for lib, keyword in js_libraries.items():
            if keyword in source_code.lower():
                table.add_row(f"✅ {lib} Detected", "Yes")

        # SEO & Analytics
        analytics_tools = {
            "Google Analytics": "google-analytics.com",
            "Facebook Pixel": "connect.facebook.net/en_US/fbevents.js",
            "Hotjar": "hotjar.com",
            "Tag Manager": "tagmanager.google.com"
        }
        for tool, keyword in analytics_tools.items():
            if keyword in source_code.lower():
                table.add_row(f"📊 {tool} Detected", "Yes")

        # Marketing Tools
        marketing_tools = {
            "MailChimp": "mailchimp.com",
            "HubSpot": "hubspot.com",
            "Klaviyo": "klaviyo.com",
            "ActiveCampaign": "activecampaign.com"
        }
        for tool, keyword in marketing_tools.items():
            if keyword in source_code.lower():
                table.add_row(f"📢 {tool} Detected", "Yes")

        # Payment Processors
        payment_processors = {
            "PayPal": "paypal.com",
            "Stripe": "stripe.com",
            "Square": "square.com",
            "Razorpay": "razorpay.com"
        }
        for processor, keyword in payment_processors.items():
            if keyword in source_code.lower():
                table.add_row(f"💳 {processor} Detected", "Yes")

        # CRM Systems
        crm_systems = {
            "Salesforce": "salesforce.com",
            "Zoho": "zoho.com",
            "HubSpot CRM": "hubspot.com"
        }
        for crm, keyword in crm_systems.items():
            if keyword in source_code.lower():
                table.add_row(f"🤝 CRM System: {crm}", "Yes")

        # CDN Detection
        cdn_providers = {
            "Cloudflare": "cloudflare",
            "Akamai": "akamai",
            "Amazon CloudFront": "cloudfront",
            "Fastly": "fastly",
            "StackPath": "stackpath"
        }
        for cdn, keyword in cdn_providers.items():
            if keyword in response.text.lower():
                table.add_row(f"🌍 CDN Provider", cdn)

        # Social Media Links
        social_media = detect_social_media_links(soup)
        for platform, links in social_media.items():
            table.add_row(f"📱 {platform} Links", ", ".join(links))

        # Print Output
        console.print("\n[bold cyan]⚡️ Generating Website Analysis... Please wait...[/bold cyan]")
        for _ in track(range(100), description="Loading...", style="green"):
            time.sleep(0.01)  # Reduced sleep time for faster animation

        console.print(table)

    except requests.exceptions.RequestException as e:
        console.print(f"[red]❌ Error: {e}[/red]")

# Example Usage
target_url = input("Enter website URL: ")
analyze_website(target_url)
