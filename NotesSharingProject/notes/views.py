from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.core.mail import EmailMessage
from django.shortcuts import render, redirect
from django.contrib import messages
# Create your views here.
from .models import Signup

from django.views import View
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from .utils import account_activation_token
from django.urls import reverse
from django.contrib import auth

def index(request):
    return render(request, 'index.html')


def about(request):
    return render(request, 'about.html')

def contact(request):
    return render(request, 'contact.html')

def userlogin(request):
    if request.method == "POST":
        u = request.POST["emailid"]
        p = request.POST["pwd"]
        user = authenticate(username=u, password=p)
        try:
            if user:
                login(request, user)
                messages.success(request,"Logged In Successfully !!!")
                return redirect('profile')
            else:
                messages.error(request, "Invalid Login Credentials, Please try Again.")
                return render(request, 'login.html')
        except:
            messages.error(request, "Something Went Wrong.")
            return render(request, 'login.html')

    return render(request, 'login.html')

def login_admin(request):
    if request.method == "POST":
        u = request.POST["uname"]
        p = request.POST["pwd"]
        user = authenticate(username=u, password=p)
        try:
            if user.is_staff:
                login(request, user)
                messages.success(request,"Logged In Successfully !!!")
                return redirect('admin_home')
            else:
                messages.error(request, "Invalid Login Credentials, Please try Again.")
                #return render(request, 'login_admin.html')
        except:
            messages.error(request, "Something Went Wrong, Please try Again.")
            return render(request, 'login_admin.html')

    return render(request, 'login_admin.html')

def signup1(request):

    if request.method == 'POST':
        f = request.POST["firstname"]
        l = request.POST["lastname"]
        c = request.POST["contact"]
        e = request.POST["emailid"]
        p = request.POST["pwd"]
        b = request.POST["branch"]
        r = request.POST["role"]
        try:
            user = User.objects.create_user(username=e, password=p, first_name=f, last_name=l)
            user.is_active = False
            user.save()
            Signup.objects.create(user=user,contact=c, branch=b, role=r)


            current_site = get_current_site(request)
            email_body = {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            }

            link = reverse('activate', kwargs={
                'uidb64': email_body['uid'], 'token': email_body['token']})

            email_subject = 'Activate your account'

            activate_url = 'http://' + current_site.domain + link

            email = EmailMessage(
                email_subject,
                'Hi ' + user.username + ', Please the link below to activate your account \n' + activate_url,
                'drwalunj.2010@gmail.com',
                [e],
            )
            email.send(fail_silently=False)
            messages.success(request, 'Account successfully created')
            return redirect('login')
        except Exception as e:
            print('error :->', e)
            messages.error(request, "Something Went Wrong, Please Try Again.")
            #return render(request, 'signup.html')

    return render(request, 'signup.html')

class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
            id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not account_activation_token.check_token(user, token):
                messages.success(request, 'Your Account already activated successfully')
                return redirect('login')

            if user.is_active:
                return redirect('login')
            user.is_active = True
            user.save()

            messages.success(request, 'Account activated successfully')
            return redirect('login')

        except Exception as ex:
            pass
        #messages.success(request, 'Your Account already activated successfully')
        return redirect('login')

def admin_home(request):
    if not request.user.is_staff:
        return redirect('login_admin')
    return render(request, 'admin_home.html')

def Logout(request):
    logout(request)
    return redirect('index')

def profile(request):
    if not request.user.is_authenticated:

        return redirect('login')

    user = User.objects.get(id=request.user.id)
    data = Signup.objects.get(user=user)
    d = {
        'data' : data,
        'user' : user
    }

    return render(request, 'profile.html', d)

def edit_profile(request):
    if not request.user.is_authenticated:
        return redirect('login')

    user = User.objects.get(id=request.user.id)
    data = Signup.objects.get(user=user)
    if request.method == 'POST':
        f = request.POST['firstname']
        l = request.POST['lastname']
        c = request.POST['contact']
        b = request.POST['branch']
        r = request.POST['role']

        user.first_name = f
        user.last_name = l
        data.contact = c
        data.branch = b
        data.role = r
        user.save()
        data.save()
        messages.success(request, "Profile Updated Successfully !!!")
        return redirect('profile')


    d = {
        'data' : data,
        'user' : user
    }

    return render(request, 'edit_profile.html', d)

def changepassword(request):
    if not request.user.is_authenticated:
        return redirect('login')
    if request.method == 'POST':
        o = request.POST['old']
        n = request.POST['new']
        c = request.POST['confirm']

        if c==n:
            u = User.objects.get(username__exact=request.user.username)
            u.set_password(n)
            u.save()
            messages.success(request,"Password Changed Succsesfully !!!")
            return redirect('logout')
        else:
            messages.error(request,"Invalid Login Credentials...")


    return render(request, 'changepassword.html')