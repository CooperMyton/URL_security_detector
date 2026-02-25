from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

def check_https(url):
    """
    Vulnerability check:
    Is the URL using insecure HTTP instead of HTTPS?
    """
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {
            "vulnerable": True,
            "issue": "Insecure protocol",
            "explanation": "This URL does not use HTTPS, meaning data sent to or from the site is not encrypted."
        }

    return {
        "vulnerable": False,
        "issue": None,
        "explanation": "This URL uses HTTPS, which encrypts data in transit."
    }

def check_reachability(url):
    """
    Basic connectivity check
    """
    try:
        response = urlopen(url, timeout=5)
        return {
            "reachable": True,
            "status_code": response.status
        }
    except HTTPError as e:
        return {
            "reachable": True,
            "status_code": e.code
        }
    except URLError as e:
        return {
            "reachable": False,
            "error": str(e.reason)
        }

def scan_url(url):
    print(f"\nScanning: {url}\n" + "-" * 40)

    https_result = check_https(url)
    reachability = check_reachability(url)

    # Report HTTPS issue
    if https_result["vulnerable"]:
        print("Vulnerability Found:")
        print(f"   - {https_result['issue']}")
        print(f"   - {https_result['explanation']}")
    else:
        print(" HTTPS Check Passed")
        print(f"   - {https_result['explanation']}")

    # Report reachability
    if reachability.get("reachable"):
        print(f"\n Site Reachable (Status Code: {reachability['status_code']})")
    else:
        print("\n Site Not Reachable")
        print(f"   - Error: {reachability['error']}")

if __name__ == "__main__":
    user_url = input("Enter a URL to scan: ").strip()

    # Auto-fix missing scheme
    if not user_url.startswith(("http://", "https://")):
        user_url = "http://" + user_url

    scan_url(user_url)
