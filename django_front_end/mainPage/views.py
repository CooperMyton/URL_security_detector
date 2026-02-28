from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from .forms import URLForm

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
        scan_results = urlText
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
