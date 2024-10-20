import re


def detect_ip(text: str):
    """
    Detects IPv4 addresses in the given text.
    Args:
        text (str): The input text to search for IP addresses.
    Returns:
        list: A list of detected IPv4 addresses.
    """
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return re.findall(ip_pattern, text)

def detect_hash(text: str):
    """
    Detects common cryptographic hashes (MD5, SHA1, SHA256) in the given text,
    excluding those found within URLs or query parameters like 'hash=' or 'sessionid='.
    Args:
        text (str): The input text to search for hashes.
    Returns:
        list: A list of detected hashes.
    """
    md5_pattern = r'(?<!hash=)(?<!sessionid=)(?<!\?|&)\\b[a-fA-F0-9]{32}\\b'
    sha1_pattern = r'(?<!hash=)(?<!sessionid=)(?<!\?|&)\\b[a-fA-F0-9]{40}\\b'
    sha256_pattern = r'(?<!hash=)(?<!sessionid=)(?<!\?|&)\\b[a-fA-F0-9]{64}\\b'
    md5_hashes = re.findall(md5_pattern, text)
    sha1_hashes = re.findall(sha1_pattern, text)
    sha256_hashes = re.findall(sha256_pattern, text)
    # Combine all detected hashes into a single list
    all_hashes = md5_hashes + sha1_hashes + sha256_hashes
    return all_hashes

def detect_email(text: str):
    """
    Detects email addresses in the given text.
    Args:
        text (str): The input text to search for email addresses.
    Returns:
        list: A list of detected email addresses.
    """
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(email_pattern, text)

def detect_url(text: str):
    """
    Detects URLs (starting with 'http://' or 'https://') in the given text.
    Args:
        text (str): The input text to search for URLs.
    Returns:
        list: A list of detected URLs.
    """
    url_pattern = r'(https?://[^\s]+)'
    return re.findall(url_pattern, text)

def detect_domain(text: str):
    """
    Detects domains in the given text, excluding full URLs that start with 'http://', 'https://', or 'ftp://'.
    Args:
        text (str): The input text to search for domains.
    Returns:
        list: A list of detected domains that are not part of full URLs.
    """
    # Regular expression for detecting URLs (http, https, ftp)
    url_pattern = r'\b(?:https?|ftp):\/\/[^\s]+'
    # Remove full URLs from the text to avoid detecting domains within URLs
    text_without_urls = re.sub(url_pattern, '', text)  
    # Regular expression for detecting domains
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+(?:[a-zA-Z]{2,})\b'
    # Find domains in the cleaned text without URLs
    return re.findall(domain_pattern, text_without_urls)


def detect_all(text: str):
    """
    Detects all IoCs (IP, hashes, emails, URLs, domains) in the given text.
    Args:
        text (str): The input text to search for IoCs.
    Returns:
        list: A unique list of all detected IoCs.
    """
    # Collect all detected IoCs
    ips = detect_ip(text)
    hashes = detect_hash(text)
    emails = detect_email(text)
    urls = detect_url(text)
    domains = detect_domain(text)
    # Combine all IoCs into a single list
    all_iocs = ips + hashes + emails + urls + domains
    # Return unique IoCs
    return list(set(all_iocs))

