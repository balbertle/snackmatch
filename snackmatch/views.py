from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from django.core.exceptions import ValidationError
from .models import User

def signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        security_answer = request.POST.get('security_answer')
        
        try:
            user = User.objects.create_user(
                username=username,
                password=password,
                security_answer=security_answer
            )
            login(request, user)
            return redirect('home')
        except IntegrityError:
            messages.error(request, 'Username already exists.')
        except ValidationError as e:
            messages.error(request, str(e))
    
    return render(request, 'auth/signup.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, 'Invalid username or password.')
    
    return render(request, 'auth/login.html')

def user_logout(request):
    if request.method == 'POST':
        logout(request)
        messages.success(request, 'You have been successfully logged out.')
    return redirect('home')

def forgot_password(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            user = User.objects.get(username=username)
            return render(request, 'auth/password_reset_question.html', {'user': user})
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
    
    return render(request, 'auth/forgot_password.html')

def password_reset_question(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        security_answer = request.POST.get('security_answer', '').strip()
        
        try:
            user = User.objects.get(username=username)
            if user.security_answer and user.security_answer.lower() == security_answer.lower():
                return render(request, 'auth/password_reset_form.html', {'username': username})
            else:
                messages.error(request, 'Incorrect security answer. Please try again.')
                return render(request, 'auth/password_reset_question.html', {'user': user})
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('forgot_password')
    
    return redirect('forgot_password')

def password_reset_form(request):
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        new_password = request.POST.get('new_password', '').strip()
        new_password2 = request.POST.get('new_password2', '').strip()

        if not username:
            messages.error(request, 'Invalid request. Please start over.')
            return redirect('forgot_password')

        if len(new_password) < 8:
            messages.error(request, 'Password must be at least 8 characters long!')
            return render(request, 'auth/password_reset_form.html', {'username': username})

        if new_password != new_password2:
            messages.error(request, 'Passwords do not match!')
            return render(request, 'auth/password_reset_form.html', {'username': username})

        try:
            user = User.objects.get(username=username)
            user.set_password(new_password)
            user.save()
            
            # Log the user in after password reset
            user = authenticate(request, username=username, password=new_password)
            if user is not None:
                login(request, user)
                messages.success(request, 'Password has been reset successfully.')
                return redirect('home')
        except User.DoesNotExist:
            messages.error(request, 'User not found.')
            return redirect('forgot_password')

    return redirect('forgot_password')

@login_required
def home(request):
    return render(request, 'home.html')
