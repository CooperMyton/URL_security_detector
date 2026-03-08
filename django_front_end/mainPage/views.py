from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .forms import URLForm
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from difflib import SequenceMatcher
import re


# Common brands frequently targeted in phishing
COMMON_BRANDS = [
    "google.com",
    "amazon.com",
    "paypal.com",
    "apple.com",
    "microsoft.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "bankofamerica.com",
    "chase.com",
    "venmo.com",
    "youtube.com"
]

#return similarity of 2 strings
def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()



#Basic url checker
def check_https(url):
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {
            "vulnerable": True,
            "issue": "Insecure Protocol (HTTP)",
            "what_it_means": "This site uses HTTP instead of HTTPS. Data sent to and from the site is not encrypted.",
            "how_detected": "The URL scheme was checked and does not use 'https://'.",
            "risk": "Attackers on the same network could intercept or modify data (man-in-the-middle attack).",
            "what_to_do": "Avoid entering passwords or sensitive data. Try manually switching to https:// if available."
        }

    return {
        "vulnerable": False,
        "issue": None,
        "what_it_means": "This site uses HTTPS, which encrypts data in transit.",
        "how_detected": "The URL scheme was verified as 'https://'.",
        "risk": "Data is encrypted during transmission.",
        "what_to_do": "Always ensure sensitive websites use HTTPS."
    }


def check_reachability(url):
    try:
        response = urlopen(url, timeout=5)
        return {
            "reachable": True,
            "status_code": response.status,
            "what_it_means": "The site responded to a connection request.",
            "how_detected": "A request was sent and the server returned a valid HTTP response.",
            "risk": "Reachability alone does not guarantee safety.",
            "what_to_do": "Still verify HTTPS and domain legitimacy."
        }
    except HTTPError as e:
        return {
            "reachable": True,
            "status_code": e.code,
            "what_it_means": "The server responded but returned an error status.",
            "how_detected": "The server returned an HTTP error code.",
            "risk": "Some error codes (like 403 or 404) may indicate restricted or missing pages.",
            "what_to_do": "Check if the URL is typed correctly."
        }

    except URLError as e:
        return {
            "reachable": False,
            "error": str(e.reason),
            "what_it_means": "The site could not be reached.",
            "how_detected": "The connection attempt to the server failed.",
            "risk": "The domain may not exist, may be offline, or could be suspicious.",
            "what_to_do": "Avoid interacting with unreachable or unknown domains."
        }

def check_suspicious_domain_format(url):
    """
    Checks for excessive hyphens or unusual symbols in the domain.
    """

    parsed = urlparse(url)
    domain = parsed.netloc

    # Remove port if present (example.com:8000)
    domain = domain.split(":")[0]

    hyphen_count = domain.count("-")

    # Check for non-alphanumeric characters besides dot and hyphen
    unusual_symbols = re.findall(r"[^a-zA-Z0-9.-]", domain)

    suspicious = False
    reasons = []

    if hyphen_count >= 2:
        suspicious = True
        reasons.append("Domain contains multiple hyphens.")

    if unusual_symbols:
        suspicious = True
        reasons.append("Domain contains unusual symbols.")

    if suspicious:
        return {
            "vulnerable": True,
            "issue": "Suspicious Domain Format",
            "what_it_means": "The domain contains multiple hyphens or unusual symbols, which are commonly used in phishing URLs.",
            "how_detected": f"The domain '{domain}' contains {hyphen_count} hyphen(s) and the following unusual characters: {unusual_symbols if unusual_symbols else 'None'}.",
            "risk": "Attackers often use extra hyphens or symbols to imitate legitimate brands (e.g., secure-paypal-login.com).",
            "what_to_do": "Carefully verify the domain spelling. Check that the root domain matches the official website before entering sensitive information.",
            "details": reasons
        }

    return {
        "vulnerable": False,
        "issue": None,
        "what_it_means": "The domain format appears normal with no excessive hyphens or suspicious symbols.",
        "how_detected": f"The domain '{domain}' was analyzed for excessive hyphens and unusual characters.",
        "risk": "No suspicious formatting patterns detected.",
        "what_to_do": "Continue verifying other security indicators like HTTPS and site legitimacy."
    }

def check_shortened_url(url):
    """
    Checks if the URL uses a known URL shortening service.
    """

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Remove port if present
    domain = domain.split(":")[0]

    # Common URL shortening services
    shortening_services = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "buff.ly",
        "adf.ly",
        "is.gd",
        "cutt.ly",
        "rebrand.ly",
        "shorturl.at"
    ]

    if domain in shortening_services:
        return {
            "vulnerable": True,
            "issue": "Shortened URL Detected",
            "what_it_means": "This URL uses a shortening service, which hides the true destination.",
            "how_detected": f"The domain '{domain}' matches a known URL shortening service.",
            "risk": "Shortened URLs conceal the final destination and are frequently used in phishing or malware campaigns.",
            "what_to_do": "Do not click shortened links from unknown sources. Use a URL expander service to preview the destination before visiting.",
        }

    return {
        "vulnerable": False,
        "issue": None,
        "what_it_means": "The URL does not use a known shortening service.",
        "how_detected": f"The domain '{domain}' was checked against a list of known URL shorteners.",
        "risk": "No shortened URL behavior detected.",
        "what_to_do": "Continue verifying other security indicators."
    }
    
def check_domain_impersonation(url):
    """
    Detects domains that attempt to impersonate well-known brands.
    """

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Remove port if present
    domain = domain.split(":")[0]
    
    # remove www prefix
    if domain.startswith("www."):
        domain = domain[4:]
        
    # extract root domain name (before the TLD)
    root_domain = domain.split(".")[0]


    best_match = None
    highest_score = 0

    for brand in COMMON_BRANDS:

        brand_root = brand.split(".")[0]

        score = similarity(root_domain, brand_root)
        if score > highest_score:
            highest_score = score
            best_match = brand

    suspicious_chars = re.findall(r"[0-9]", root_domain)

    # threshold for similarity detection
    if highest_score > 0.75 and root_domain != best_match.split(".")[0]:


        return {
            "vulnerable": True,
            "issue": "Possible Brand Impersonation",
            "what_it_means": "This domain looks similar to a well-known brand and may be attempting to impersonate it.",
            "how_detected": f"The domain '{root_domain}' is similar to '{best_match}' with a similarity score of {round(highest_score,2)}.",
            "risk": "Attackers often create domains that look nearly identical to trusted brands to trick users into entering credentials or personal information.",
            "what_to_do": "Carefully inspect the spelling of the domain. Visit the official website directly instead of clicking links from emails or messages.",
            "visual_domain": " ".join(domain),
            "matched_brand": best_match
        }

    return {
        "vulnerable": False,
        "issue": None,
        "what_it_means": "No strong similarity to commonly impersonated brands was detected.",
        "how_detected": f"The domain '{domain}' was compared against a list of commonly impersonated brands.",
        "risk": "No brand impersonation patterns detected.",
        "what_to_do": "Continue verifying other indicators such as HTTPS and suspicious keywords.",
        "visual_domain": " ".join(domain)
    }


def check_ip_domain(url):
    """
    Detects URLs that use an IP address instead of a domain name.
    """

    parsed = urlparse(url)
    domain = parsed.netloc

    # remove port if present
    domain = domain.split(":")[0]

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):

        return {
            "vulnerable": True,
            "issue": "IP Address Used Instead of Domain",
            "what_it_means": "This URL uses a numeric IP address instead of a recognizable domain name.",
            "how_detected": f"The domain '{domain}' matches the pattern of an IPv4 address.",
            "risk": "Attackers sometimes use IP addresses to hide the true identity of a website. This can make phishing pages harder to recognize because users cannot see a familiar brand name.",
            "what_to_do": "Avoid entering sensitive information on websites that use raw IP addresses. If you believe the site may be legitimate, try searching for the official domain name instead.",
            "visual_domain": " ".join(domain)
        }

    return {
        "vulnerable": False,
        "issue": None,
        "what_it_means": "The URL does not use a raw IP address as its domain.",
        "how_detected": f"The domain '{domain}' was checked to see if it matches an IP address pattern.",
        "risk": "No IP-based domain pattern detected.",
        "what_to_do": "Continue checking other indicators such as HTTPS, suspicious keywords, and shortened URLs.",
        "visual_domain": " ".join(domain)
    }
    

def check_suspicious_keywords(url):
    """
    Detects phishing-related keywords commonly used in malicious URLs.
    """

    suspicious_keywords = [
        "login",
        "verify",
        "update",
        "secure",
        "account",
        "bank",
        "signin",
        "password",
        "confirm"
    ]

    parsed = urlparse(url)
    full_url = url.lower()

    matched_keywords = []

    for keyword in suspicious_keywords:
        if keyword in full_url:
            matched_keywords.append(keyword)

    if matched_keywords:

        return {
            "vulnerable": True,
            "issue": "Suspicious Keywords Detected in URL",

            "what_it_means": "The URL contains words that are commonly used in phishing attacks to pressure users into entering personal or financial information.",

            "how_detected": f"The following suspicious keywords were found in the URL: {', '.join(matched_keywords)}.",

            "risk": "Attackers frequently use words like 'login', 'verify', or 'secure' to trick users into believing they must urgently confirm account details. This can lead to stolen passwords or financial information.",

            "what_to_do": "Before clicking links that ask you to login or verify your account, visit the official website directly by typing the domain into your browser instead of following the link.",

            "visual_domain": " ".join(url)
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": "No common phishing-related keywords were found in the URL.",

        "how_detected": "The URL was scanned for common phishing words such as login, verify, update, secure, and account.",

        "risk": "No suspicious keywords were detected.",

        "what_to_do": "Even if no suspicious keywords appear, users should still verify the domain name and ensure the site is legitimate.",

        "visual_domain": " ".join(url)
    }
    

def check_tld(url):
    """
    Detects suspicious Top Level Domains (TLDs) that are commonly abused in phishing attacks.
    """

    suspicious_tlds = [
        "xyz",
        "top",
        "club",
        "online",
        "site",
        "info",
        "cc",
        "biz",
        "ru",
        "tk"
    ]

    parsed = urlparse(url)
    domain = parsed.netloc

    # remove port if present
    domain = domain.split(":")[0]

    # extract TLD
    if "." in domain:
        tld = domain.split(".")[-1].lower()
    else:
        tld = ""

    if tld in suspicious_tlds:

        return {
            "vulnerable": True,
            "issue": "Suspicious Top Level Domain Detected",

            "what_it_means": f"The website uses the .{tld} top level domain, which is commonly used in phishing attacks.",

            "how_detected": f"The domain '{domain}' was analyzed and the TLD '.{tld}' matched a list of commonly abused domains.",

            "risk": "Phishing websites frequently register inexpensive or less regulated domain extensions. Attackers use these domains to create fake login pages that imitate legitimate services.",

            "what_to_do": "Be cautious when visiting websites that use unfamiliar domain extensions. If the site claims to represent a major company, verify that you are using their official domain.",

            "visual_domain": " ".join(domain)
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": f"The website uses the .{tld} top level domain, which is commonly used by legitimate organizations.",

        "how_detected": f"The domain '{domain}' was checked and its TLD '.{tld}' did not match commonly abused phishing domain extensions.",

        "risk": "No suspicious top level domain was detected.",

        "what_to_do": "Even trusted domain extensions can still host malicious sites, so always check the full domain name carefully.",

        "visual_domain": " ".join(domain)
    }
    

def check_subdomains(url):
    """
    Detects suspicious subdomain usage commonly seen in phishing URLs.
    """

    suspicious_keywords = [
        "login",
        "secure",
        "verify",
        "account",
        "update",
        "bank",
        "signin"
    ]

    parsed = urlparse(url)
    domain = parsed.netloc

    # remove port if present
    domain = domain.split(":")[0]

    parts = domain.split(".")

    subdomains = []

    if len(parts) > 2:
        subdomains = parts[:-2]

    suspicious_found = []

    for sub in subdomains:
        for keyword in suspicious_keywords:
            if keyword in sub.lower():
                suspicious_found.append(sub)

    if len(subdomains) > 3 or suspicious_found:

        return {
            "vulnerable": True,
            "issue": "Suspicious Subdomain Structure Detected",

            "what_it_means": "The URL contains multiple or misleading subdomains that may be used to disguise the true website address.",

            "how_detected": f"The domain '{domain}' contains {len(subdomains)} subdomains. Suspicious subdomains found: {', '.join(suspicious_found) if suspicious_found else 'None'}",

            "risk": "Attackers often create long chains of subdomains to trick users into believing they are visiting a trusted site. For example, a phishing URL might start with 'paypal.login.secure...' even though the actual domain belongs to an attacker.",

            "what_to_do": "Always check the last two parts of a domain name (for example example.com). This is the real website. Anything before it may just be a subdomain.",

            "visual_domain": " ".join(domain)
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": "The domain structure does not contain an excessive number of subdomains.",

        "how_detected": f"The domain '{domain}' was analyzed and contains {len(subdomains)} subdomains.",

        "risk": "No suspicious subdomain patterns were detected.",

        "what_to_do": "Continue verifying other security indicators such as HTTPS, domain spelling, and suspicious keywords.",

        "visual_domain": " ".join(domain)
    }



def mainQueryPage(request):
    template = loader.get_template("test_template.html")

    if request.method == "POST":
        #we got a url to parse
        form = URLForm(request.POST)
        urlText = "INVALID"
        if form.is_valid():
            urlText = form.cleaned_data["urlBox"]
        else:
            #raise some kind of error
            urlText = "there was an error" 
        # here we pass the url text to the checker
        # then we pass the scan results to the html
        #for now, lets just pass the url on
        # Auto-add scheme if missing
        if not urlText.startswith(("http://", "https://")):
            urlText = "http://" + urlText

        https_result = check_https(urlText)
        reachability = check_reachability(urlText)
        domain_format = check_suspicious_domain_format(urlText)
        shortened_url = check_shortened_url(urlText)
        domain_impersonation = check_domain_impersonation(urlText)
        ip_domain = check_ip_domain(urlText)
        suspicious_keywords = check_suspicious_keywords(urlText)
        tld_analysis = check_tld(urlText)
        subdomain_analysis = check_subdomains(urlText)


        scan_results = {
            "url": urlText,
            "https_result": https_result,
            "reachability": reachability,
            "domain_format": domain_format,
            "shortened_url": shortened_url,
            "domain_impersonation": domain_impersonation,
            "ip_domain": ip_domain,
            "suspicious_keywords": suspicious_keywords,
            "tld_analysis": tld_analysis,
            "subdomain_analysis": subdomain_analysis
        }

        form = URLForm()
        context = {
            'scan_results' : scan_results,
            'url_form' : form
        }

        return render(request, "test_template.html", context=context)
    else:
        form = URLForm()
        context = {
            'scan_results' : "",
            'url_form' : form
        }
        return render(request, "test_template.html", context=context)
