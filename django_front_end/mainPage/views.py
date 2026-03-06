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


        scan_results = {
            "url": urlText,
            "https_result": https_result,
            "reachability": reachability,
            "domain_format": domain_format,
            "shortened_url": shortened_url,
            "domain_impersonation": domain_impersonation
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
