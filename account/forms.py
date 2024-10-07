from django import forms 
from django.contrib.auth.forms import UserCreationForm
from .models import User, Document, Pubs


class LoginForm(forms.Form):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control"
            }
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control"
            }
        )
    )
    remember_me = forms.BooleanField(required=True)

    
class SignUpForm(UserCreationForm):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control"
            }
        )
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control"
            }
        )
    )     
    password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control"
            }
        )
    ) 
    email = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control"
            }
        )
    )
    
    code = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                "class": "form-control"
            }
        )
    )

    class Meta:
        model = User 
        fields = ('username','email','password1','password2','code','is_admin','is_teacher','is_student')

class DocumentForm(forms.ModelForm):
    pdf = forms.FileField(widget = forms.TextInput(attrs={
        "name": "pdf_files",  # Name attribute for the input field
        "type": "file",        # Input type
        "class": "form-control",  # Bootstrap class for styling
        "multiple": True,      # Allowing multiple files to be selected
        "accept": ".pdf",      # Limiting to PDF files
    }), label="")              # Label for the field (optional)

    class Meta:
        model = Document  # Assuming Document is the model associated with PDF files
        fields = ['pdf']   # Field(s) to include in the form

class PubsForm(forms.ModelForm):
    class Meta:
        model = Pubs
        fields = ['auth', 'pub_title', 'topic', 'pub_date']

