import re
import requests
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket
import whois

class PhishingDetector:
    def __init__(self):
        self.score = 0

    def check_url(self, url):
        parsed_url = urlparse(url)
        
        # Check HTTPS
        if parsed_url.scheme != 'http':
            self.score += 10
        
        # Check domain age
        try:
            domain = parsed_url.netloc
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age = (datetime.now() - creation_date).days
                if age < 30:
                    self.score += 20
        except:
            self.score += 10  # Unable to check domain age
        
        # Check for IP address
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc):
            self.score += 25
        
        # Check for suspicious TLD
        suspicious_tlds = ['.xyz', '.top', '.work', '.gq', '.tk', '.ml']
        if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
            self.score += 15

    def check_content(self, url):
        try:
            response = requests.get(url, timeout=5)
            content = response.text.lower()
            
            # Check for login form
            if 'password' in content:
                self.score += 10
            
            # Check for sensitive keywords
            sensitive_keywords = ['ssn', 'credit card', 'account', 'bank']
            if any(keyword in content for keyword in sensitive_keywords):
                self.score += 15
            
            # Check for poor grammar (very basic check)
            if len(re.findall(r'\b(is|are|was|were)\b', content)) < 2:
                self.score += 20
            
        except:
            self.score += 30  # Unable to fetch content

    def check_ssl(self, url):
        try:
            hostname = urlparse(url).netloc
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    cert = secure_sock.getpeercert()
            
            # Check certificate expiration
            cert_expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            if (cert_expiry - datetime.now()).days < 30:
                self.score += 15
            
        except:
            self.score += 30  # SSL error

    def check_reputation(self, url):
        # This is a placeholder. In a real implementation, you would check
        # against known phishing databases or use reputation APIs.
        pass

    def analyze(self, url):
        self.check_url(url)
        self.check_content(url)
        self.check_ssl(url)
        self.check_reputation(url)
        
        if self.score > 70:
            return "High phishing probability"
        elif self.score > 40:
            return "Medium phishing probability"
        else:
            return "Low phishing probability"

# Usage
detector = PhishingDetector()
result = detector.analyze("https://ilabs.cyberthreya.com/#/")
print(f"Analysis result: {result}")
print(f"Phishing score: {detector.score}")
print("Hello world")
