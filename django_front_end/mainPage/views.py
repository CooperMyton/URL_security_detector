from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .forms import URLForm
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError, HTTPError

#Basic url checker
def check_https(url):
    parsed = urlparse(url)

    if parsed.scheme != "https":
        return {
            "vulnerable": True,
            "issue": "Insecure protocol",
            "explanation": "This URL does not use HTTPS, meaning data is not encrypted."
        }

    return {
        "vulnerable": False,
        "issue": None,
        "explanation": "This URL uses HTTPS."
    }


def check_reachability(url):
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

        scan_results = {
            "url": urlText,
            "https_result": https_result,
            "reachability": reachability
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
