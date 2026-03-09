from django import forms

class URLForm(forms.Form):
    urlBox = forms.CharField(
        label="",
        max_length=300,
        widget=forms.TextInput(attrs={
            "class": "url-input",
            "placeholder": "Enter URL to check"
        }))