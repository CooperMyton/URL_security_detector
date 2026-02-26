from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader

def mainQueryPage(request):
    template = loader.get_template("test_template.html")
    return HttpResponse(template.render())
