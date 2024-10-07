from django.shortcuts import render, redirect, get_object_or_404
from django.template import loader

from .forms import SignUpForm, LoginForm, DocumentForm
from django.contrib.auth import authenticate, login, logout

from django.http import JsonResponse, HttpResponseBadRequest, HttpResponse, HttpResponseServerError
from django.conf import settings
import os

from .models import Document, User, Courses, Pubs
from .forms import PubsForm

from django.http import HttpResponse
from django.core.mail import send_mail

from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden


def simple(request):
    send_mail(subject='this is a test',
    message='message body',
    from_email='django@demomailtrap.com',
    recipient_list=['cse.department.webpage.2024@gmail.com'])
    return HttpResponse('Mail sent!')
    

# from django.contrib.auth.forms import PasswordResetForm
# from django.contrib.auth.tokens import default_token_generator
# from django.core.mail import send_mail
# from django.template.loader import render_to_string
# from django.utils.http import urlsafe_base64_encode
# from django.utils.encoding import force_bytes

# from django.contrib.auth.forms import SetPasswordForm
# from django.utils.encoding import force_text
# from django.contrib import messages


def register(request):
    msg = None
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            email = form.cleaned_data['email']
            code = form.cleaned_data['code']
            is_admin = form.cleaned_data['is_admin']
            is_student = form.cleaned_data['is_student']
            is_teacher = form.cleaned_data['is_teacher']
            
            # Validate the code

            if is_admin and not code=='123456':
                msg = 'Wrong Code'
            elif is_teacher and not code=='654321':
                msg = 'Wrong Code'
            else:
                # Create user
                user = User.objects.create_user(username=username, password=password)
                if not (is_admin or is_teacher or is_student):
                    is_student = True
                user.is_admin = is_admin
                user.is_student = is_student
                user.is_teacher = is_teacher
                user.save()
                msg = 'User created successfully'
                return redirect('login_view')
        else:
            msg = 'form is not valid'
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form, 'msg':msg})


def login_view(request):
    form = LoginForm(request.POST or None)
    msg = None
    if request.method == "POST":
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            remember_me = form.cleaned_data.get('remember_me')

            if remember_me: 
            # This if statement can change, 
            # but the purpose is checking remember me checkbox is checked or not.
                request.session.set_expiry(604800) # Here we extend session.
            else:
                # This part of code means, close session when browser is closed.
                request.session.set_expiry(0) 
            
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                # if not remember_me:
                #     # Here if the remember me is False, that is why expiry is set to 0 seconds. 
                #     # So it will automatically close the session after the browser is closed.
                #     request.session.set_expiry(0)  
                # # else browser session will be as long as the session  cookie time "SESSION_COOKIE_AGE"
                return redirect('homepage')
            else:
                msg = 'invalid credentials'
        else:
            msg = 'error validating the form'
    elif request.user.is_authenticated: 
            return redirect('homepage')
    return render(request, 'login.html', {'form': form, 'msg': msg})

def custom_logout(request):
    logout(request)
    return redirect('login_view')
    
# def forgot_password(request):
#     if request.method == 'POST':
#         form = PasswordResetForm(request.POST)
#         if form.is_valid():
#             email = form.cleaned_data['email']
#             # Get user by email
#             user = User.objects.filter(email=email).first()
#             if user is not None:
#                 # Generate token
#                 token = default_token_generator.make_token(user)
#                 # Generate password reset URL
#                 uid = urlsafe_base64_encode(force_bytes(user.pk))
#                 reset_url = request.build_absolute_uri(f'/reset_password/{uid}/{token}/')
#                 # Send password reset email
#                 subject = 'Reset Your Password'
#                 message = render_to_string('password_reset_email.html', {'reset_url': reset_url})
#                 send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
#             # Redirect to a confirmation page
#             return render(request, 'password_reset_confirm.html')
#     else:
#         form = PasswordResetForm()
#     return render(request, 'forgot_password.html', {'form': form})



# def reset_password(request, uidb64, token):
#     try:
#         # Decode user ID
#         uid = force_text(urlsafe_base64_decode(uidb64))
#         # Get user by ID
#         user = User.objects.get(pk=uid)
#     except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#         user = None

#     # Check if the user and token are valid
#     if user is not None and default_token_generator.check_token(user, token):
#         if request.method == 'POST':
#             form = SetPasswordForm(user, request.POST)
#             if form.is_valid():
#                 form.save()
#                 messages.success(request, 'Password reset successfully. You can now log in with your new password.')
#                 return redirect('login_view')
#         else:
#             form = SetPasswordForm(user)
#         return render(request, 'reset_password.html', {'form': form})
#     else:
#         messages.error(request, 'The password reset link is invalid or has expired.')
#         return redirect('forgot_password')

def delete_course(request, course_id):
    course = get_object_or_404(Courses, pk=course_id)
    course.delete()
    return redirect('homepage')

def delete_pub(request, pub_id):
    pub = get_object_or_404(Pubs, pk=pub_id)
    pub.delete()
    return redirect('homepage')

def add_course(request):
    if request.method == 'POST':
        cname = request.POST.get('cname')
        c_code = request.POST.get('c_code')
        cred = request.POST.get('cred')
        # Validate and save the course
        course = Courses(cname=cname, c_code=c_code, cred=cred)
        course.save()
        return redirect('homepage')
    return HttpResponse('Method not allowed', status=405)

def add_pub(request):
    if request.method == 'POST':
        auth = request.POST.get('auth')
        pub_title = request.POST.get('pub_title')
        topic = request.POST.get('topic')
        pub_date = request.POST.get('pub_date')
        print(auth,pub_title,topic,pub_date)
        # Validate and save the publication
        pub = Pubs(auth=auth, pub_title=pub_title, topic=topic, pub_date=pub_date)
        pub.save()
        return redirect('homepage')
    return HttpResponse('Method not allowed', status=405)

@login_required
def homepage(request):
    num_students = User.objects.filter(is_student=True).count()
    num_teachers = User.objects.filter(is_teacher=True).count()
    data = Courses.objects.all().order_by('-id').values()
    data2 = Pubs.objects.all().order_by('-id').values()
    num_courses = Courses.objects.count()
    num_pubs = Pubs.objects.count()

    is_teacher_perm, is_admin_perm = False, False
    if request.user.is_teacher:
        is_teacher_perm = True
    if request.user.is_admin:
        is_admin_perm = True

    context = {
        'Courses':data,
        'Pubs':data2,
        'Branches':3,
        'num_students': num_students, 
        'num_teachers': num_teachers,
        'num_pubs': num_pubs,
        'num_courses': num_courses,
        'is_teacher_perm': is_teacher_perm,
        'is_admin_perm': is_admin_perm,
    }
    template = loader.get_template('homepage.html')
    return HttpResponse(template.render(context=context,request=request))

# def homepage(request):
#     return render(request, 'homepage1.html')

@login_required
def timetable(request):
    return render(request, 'timetable.html')

# ---------------- important documents page ----------------------


@login_required
def important_documents(request):
    # Check if the user is authenticated
    if request.user.is_authenticated:
        # Get all documents
        documents = Document.objects.all().order_by('-id')
        # Check if the user is a teacher or admin
        if request.user.is_teacher or request.user.is_admin:
            uploadform = DocumentForm(request.POST, request.FILES)
            # If the user is a teacher or admin, allow upload and delete functionalities
            if request.method == 'POST' and request.FILES.getlist('pdf'):
                pdf_files = request.FILES.getlist('pdf')
                for pdf_file in pdf_files:
                    Document.objects.create(file=pdf_file, name=pdf_file.name)
                return redirect('important_documents')  # Redirect to the same page after upload

            # Render the template with upload and delete functionalities
            return render(request, 'important_documents.html', {'documents': documents, 'allow_upload_delete': True, 'uploadform':uploadform})
        else:
            # If the user is a student, only allow viewing of documents
            return render(request, 'important_documents.html', {'documents': documents, 'allow_upload_delete': False})
    else:
        # If the user is not authenticated, redirect to login page
        return redirect('login_view')

@login_required
def list_documents(request):
    documents = Document.objects.all()
    return render(request, 'important_documents.html', {'documents': documents})

@login_required
def view_document(request, document_id):
    document = Document.objects.get(id=document_id)
    # Assuming the file is stored in the 'documents' directory within the media root
    document_path = document.file.path
    with open(document_path, 'rb') as f:
        response = HttpResponse(f.read(), content_type='application/pdf')  # Adjust content_type based on the file type
        response['Content-Disposition'] = 'inline; filename=' + document.name
    return response

@login_required
def delete_document(request, document_id):
    document = get_object_or_404(Document, id=document_id)
    document_path = document.file.path
    document.delete()
    try:
        os.remove(document_path)
    except OSError as e:
        # If there's an error deleting the file, log it or handle it accordingly
        return HttpResponseServerError("Error deleting file: {}".format(e))
    return redirect('important_documents')  # Redirect to the list of documents after deletion


