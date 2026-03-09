from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .forms import URLForm
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen
from urllib.error import URLError, HTTPError
from difflib import SequenceMatcher
import re
import os


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


def load_malicious_domains():
    """
    Loads the malicious domain list from file.
    """

    file_path = os.path.join(os.path.dirname(__file__), "resources/malicious_domains_polska_3-8-2026.txt")

    domains = set()

    with open(file_path, "r") as f:
        for line in f:
            domain = line.strip().lower()
            if domain:
                domains.add(domain)

    return domains


MALICIOUS_DOMAINS = load_malicious_domains()


def check_known_malicious_domain(url):
    """
    Checks whether a domain appears in the Polska malicious domain list.
    """

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    domain = domain.split(":")[0]

    if domain in MALICIOUS_DOMAINS:

        return {
            "vulnerable": True,
            "issue": "Domain Found in Known Malicious Domain List",

            "what_it_means": "This domain appears in a known malicious domain database. Security researchers and organizations maintain these lists to track domains that have been associated with phishing, scams, malware distribution, or other cyber threats.",

            "how_detected": f"The domain '{domain}' matched an entry in the Polska malicious domain list.",

            "risk": "Domains that appear in threat intelligence lists have previously been reported for malicious activity. Visiting these sites could expose users to phishing attacks, malware downloads, or credential theft.",

            "what_to_do": "Do not enter personal or financial information on this website. It is safest to avoid visiting domains that appear in known malicious domain lists.",

            "visual_domain": " ".join(domain)
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": "The domain was not found in the known malicious domain list used by this scanner.",

        "how_detected": f"The domain '{domain}' was compared against entries in the Polska malicious domain list.",

        "risk": "Not appearing in a malicious domain list does not guarantee that a site is safe. New malicious domains appear frequently and may not yet be reported.",

        "what_to_do": "Continue reviewing other security indicators such as HTTPS, suspicious keywords, and domain structure.",

        "visual_domain": " ".join(domain)
    }

def check_url_path(url):
    """
    Analyzes the URL path for suspicious patterns commonly used in phishing URLs.
    """

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "bank",
        "password",
        "confirm"
    ]

    parsed = urlparse(url)
    path = parsed.path.lower()

    matched_keywords = []

    for keyword in suspicious_keywords:
        if keyword in path:
            matched_keywords.append(keyword)

    folder_count = path.count("/")

    if matched_keywords or folder_count > 5 or len(path) > 60:

        return {
            "vulnerable": True,
            "issue": "Suspicious URL Path Detected",

            "what_it_means": "The path portion of the URL contains patterns commonly used in phishing links.",

            "how_detected": f"The path '{path}' contains {folder_count} folders and the following suspicious keywords: {', '.join(matched_keywords) if matched_keywords else 'None'}",

            "risk": "Attackers often include words like 'login', 'secure', or 'verify' in the URL path to trick users into thinking the link leads to a legitimate login page.",

            "what_to_do": "Always verify the domain name before trusting the path of a URL. Even if the path looks legitimate, the domain itself may belong to an attacker.",

            "visual_domain": " ".join(path) if path else "(no path present)"
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": "The URL path does not contain suspicious patterns.",

        "how_detected": f"The path '{path}' was analyzed for suspicious keywords and excessive folder depth.",

        "risk": "No suspicious patterns were detected in the URL path.",

        "what_to_do": "Continue reviewing other parts of the URL such as the domain name and query parameters.",

        "visual_domain": " ".join(path) if path else "(no path present)"
    }


def check_query_string(url):
    """
    Analyzes the query string portion of a URL for suspicious patterns.
    """

    suspicious_keywords = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "bank",
        "password",
        "confirm",
        "session",
        "token"
    ]

    parsed = urlparse(url)
    query = parsed.query.lower()

    params = parse_qs(query)

    matched_keywords = []

    for keyword in suspicious_keywords:
        if keyword in query:
            matched_keywords.append(keyword)

    param_count = len(params)
    query_length = len(query)

    if matched_keywords or param_count > 5 or query_length > 80:

        return {
            "vulnerable": True,
            "issue": "Suspicious Query String Detected",

            "what_it_means": "The query string portion of the URL contains patterns commonly associated with phishing or tracking links.",

            "how_detected": f"The query string '{query}' contains {param_count} parameters and the following suspicious keywords: {', '.join(matched_keywords) if matched_keywords else 'None'}",

            "risk": "Phishing URLs often include parameters such as 'verify', 'account', or 'session' to make links appear legitimate or to pass stolen credentials to attackers.",

            "what_to_do": "Be cautious when clicking links with long or complex query parameters. If the link claims to require login or verification, navigate to the website directly instead of following the link.",

            "visual_domain": " ".join(query) if query else "(no query string present)"
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": "The URL query string does not contain suspicious patterns.",

        "how_detected": f"The query string '{query}' was analyzed for suspicious keywords and excessive parameters.",

        "risk": "No suspicious query string patterns were detected.",

        "what_to_do": "Even normal-looking parameters can sometimes be used for tracking or redirects, so always verify the domain name of the website.",

        "visual_domain": " ".join(query) if query else "(no query string present)"
    }
    


def check_anchor(url):
    """
    Analyzes the anchor (fragment) portion of a URL for suspicious patterns.
    """

    suspicious_keywords = [
        "login",
        "secure",
        "verify",
        "account",
        "bank",
        "update",
        "password",
        "confirm"
    ]

    parsed = urlparse(url)
    anchor = parsed.fragment.lower()

    matched_keywords = []

    for keyword in suspicious_keywords:
        if keyword in anchor:
            matched_keywords.append(keyword)

    if matched_keywords or len(anchor) > 30:

        return {
            "vulnerable": True,
            "issue": "Suspicious URL Anchor Detected",

            "what_it_means": "The anchor portion of the URL contains patterns that may attempt to make the link appear more trustworthy.",

            "how_detected": f"The anchor '{anchor}' contains the following suspicious keywords: {', '.join(matched_keywords) if matched_keywords else 'None'}",

            "risk": "Although anchors are processed only by the browser, attackers sometimes use them to make links look more legitimate or to mimic real website navigation.",

            "what_to_do": "Users should focus on verifying the domain name of the website rather than trusting the additional text that appears after the '#' symbol.",

            "visual_domain": " ".join(anchor) if anchor else "(no anchor present)"
        }

    return {
        "vulnerable": False,
        "issue": None,

        "what_it_means": "No suspicious patterns were detected in the anchor portion of the URL.",

        "how_detected": f"The anchor '{anchor}' was analyzed for suspicious keywords and unusual length.",

        "risk": "No suspicious anchor patterns were detected.",

        "what_to_do": "Even though anchors are generally harmless, users should still verify the domain name of the website before trusting a link.",

        "visual_domain": " ".join(anchor) if anchor else "(no anchor present)"
    }
    
def calculate_risk_score(scan_results):
    """
    Calculates an overall phishing risk score based on the number of vulnerabilities detected.
    """

    warnings = 0

    checks = [
        "https_result",
        "domain_format",
        "shortened_url",
        "domain_impersonation",
        "ip_domain",
        "suspicious_keywords",
        "tld_analysis",
        "subdomain_analysis",
        "malicious_domain_list",
        "path_analysis",
        "query_analysis",
        "anchor_analysis"
    ]

    for check in checks:
        result = scan_results.get(check)
        if result and result.get("vulnerable"):
            warnings += 1

    if warnings >= 6:
        level = "HIGH"
        color = "red"
    elif warnings >= 3:
        level = "MEDIUM"
        color = "orange"
    else:
        level = "LOW"
        color = "green"

    return {
        "warnings": warnings,
        "level": level,
        "color": color,

        "what_it_means": "This score summarizes how many phishing indicators were detected in the URL.",

        "how_detected": f"The scanner identified {warnings} potential phishing indicators across multiple URL analysis checks.",

        "risk": "A higher score indicates that multiple suspicious characteristics were found in the URL.",

        "what_to_do": "If a URL shows a medium or high risk score, it is best to avoid entering personal information or credentials on that site."
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
        malicious_domain_list = check_known_malicious_domain(urlText)
        path_analysis = check_url_path(urlText)
        query_analysis = check_query_string(urlText)
        anchor_analysis = check_anchor(urlText)


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
            "subdomain_analysis": subdomain_analysis,
            "malicious_domain_list": malicious_domain_list,
            "path_analysis": path_analysis,
            "query_analysis": query_analysis,
            "anchor_analysis": anchor_analysis
        }
        scan_results["risk_score"] = calculate_risk_score(scan_results)


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
