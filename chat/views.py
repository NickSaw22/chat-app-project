import json
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.http.response import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.renderers import JSONRenderer
from .models import Message
from .forms import SignUpForm
from .serializers import MessageSerializer, UserSerializer
from cryptography.fernet import Fernet


def index(request):
    if request.user.is_authenticated:
        return redirect('chats')
    if request.method == 'GET':
        return render(request, 'chat/index.html', {})
    if request.method == "POST":
        username, password = request.POST['username'], request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
        else:
            return HttpResponse('{"error": "User does not exist"}')
        return redirect('chats')


@csrf_exempt
def message_list(request, sender=None, receiver=None):
    """
    List all required messages, or create a new message.
    """
    if request.method == 'GET':
        messages = list(Message.objects.filter(sender_id=sender, receiver_id=receiver, is_read=False))
        # print('get query: ', messages)
        # print(type(messages))
        li_mess = []

        for message in messages:
            print('for loop msg:', message)
            # print(type(message))
            c = str(message)
            strip_s = c.strip('"')
            # print(strip_s)
            # print(type(strip_s))
            s1 = strip_s[1:]
            # print(s1)
            s1_rep = s1.replace("'", "")
            # print(s1_rep)
            # print(type(s1_rep))
            # print(type(c))
            res = bytes(s1_rep, 'utf-8')
            # print(res)
            # print(type(res))

            mess = decrypt_message(res)
            print('Decrypted message: ', mess)
            print('og from db:', message)
            print('using ast or json:', message)
            li_mess.append({
                "sender": message.sender,
                "receiver": message.receiver,
                "message": mess,
                "timestamp": message.timestamp,
                "is_read": True,
            })
            # print(message)
            message.is_read = True
            message.save()

        print('li_mess:', li_mess)
        print('Type:', type(li_mess))

        serializer = MessageSerializer(li_mess, many=True, context={'request': request})

        # print(data)
        # print('Serializer: ', serializer.data)

        return JsonResponse(serializer.data, safe=False)

    elif request.method == 'POST':
        data = JSONParser().parse(request)
        print('Before encrypting(post):', data)
        # print(type(data['message']))
        m = data.get('message')
        # print(type(m))
        enc = encrypt_message(m)
        data['message'] = enc
        # print(type(enc))
        data.update({'message': str(data.get('message'))})
        # print(type(data['message']))
        print('Saved to database(post):', data)
        serializer = MessageSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return JsonResponse(serializer.data, status=201)
        print(serializer.errors)
        return JsonResponse(serializer.errors, status=400)


def register_view(request):
    """
    Render registration template
    """
    if request.method == 'POST':
        print("working1")
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            username = form.cleaned_data['username']
            password = form.cleaned_data['password1']
            user.set_password(password)
            user.save()
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect('chats')
    else:
        print("working2")
        form = SignUpForm()
    template = 'chat/register.html'
    context = {'form': form}
    return render(request, template, context)


def chat_view(request):
    if not request.user.is_authenticated:
        return redirect('index')
    if request.method == "GET":
        return render(request, 'chat/chat.html',
                      {'users': User.objects.exclude(username=request.user.username)})


def message_view(request, sender, receiver):
    if not request.user.is_authenticated:
        return redirect('index')
    if request.method == "GET":
        messages = list(Message.objects.filter(sender_id=sender, receiver_id=receiver) |
                        Message.objects.filter(sender_id=receiver, receiver_id=sender))

        li_mess = []

        for message in messages:

            c = str(message)
            strip_s = c.strip('"')

            s1 = strip_s[1:]

            s1_rep = s1.replace("'", "")

            res = bytes(s1_rep, 'utf-8')

            mess = decrypt_message(res)
            print('Decrypted message: ', mess)
            print('og from db:', message)

            li_mess.append({
                "sender": message.sender,
                "receiver": message.receiver,
                "message": mess,
            })
            # print(message)
        print('li_mess:', li_mess)
        print('Type:', type(li_mess))

        return render(request, "chat/messages.html",
                      {'users': User.objects.exclude(username=request.user.username),
                       'receiver': User.objects.get(id=receiver),
                       'messages': li_mess})

def load_key():
    return open("secret.key", "rb").read()


def encrypt_message(message):
    key = load_key()
    encoded_msg = message.encode()
    f = Fernet(key)
    encrypted_msg = f.encrypt(encoded_msg)
    return encrypted_msg


def decrypt_message(enc_msg):
    key = load_key()
    f = Fernet(key)
    dec_msg = f.decrypt(enc_msg)
    return dec_msg.decode()
