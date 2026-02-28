from django.shortcuts import render
from django.http import HttpResponse
from django.template import loader

def resourcesPage(request):
    template = loader.get_template("resources_mainpage.html")
    return HttpResponse(template.render())