from django import forms

class URLForm(forms.Form):
    urlBox = forms.CharField(label="URL" ,max_length=300)