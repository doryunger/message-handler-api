from django.contrib.auth import authenticate, login,logout
from django.db.models import Q
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view,permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.status import (HTTP_400_BAD_REQUEST,HTTP_401_UNAUTHORIZED,HTTP_200_OK)
from rest_framework.response import Response
from .models import Message
import ast

#A login request which uses the authentication infrastructure of Django
@api_view(['POST'])
@permission_classes((AllowAny,))
def login_user(request):
    output={}
    username = request.POST["username"]
    password = request.POST["password"]
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        #Initialize a session variable of 'current' message will be used later on
        request.session['msgnum'] = -1
        #Validating the log in process
        if request.user.is_authenticated:
            token, _ = Token.objects.get_or_create(user=user)
            output['token'] = token.key
            output['note'] = 'Logged in'
            return Response(output,status=HTTP_200_OK)
    else:
        output['note']='log in failed'
        return Response(output, status=HTTP_400_BAD_REQUEST)


#A logut request which uses the authentication infrastructure of Django
@api_view(['POST'])
@permission_classes((AllowAny,))
def logout_user(request):
    output={}
    username = validateUser(request)
    if username != None:
        print(request.user)
        request.user.auth_token.delete()
        logout(request)
        output['token'] = None
        output['note'] = username + ' logged out'
        return Response(output, status=HTTP_200_OK)
    else:
        output['note'] = 'User is unauthorized to perform this action'
        return Response(output, status=HTTP_401_UNAUTHORIZED)


 #A service method that Validates whether a user is logged in or not
def validateUser(request):
    if request.user.is_authenticated:
        print('Hello, you are logged in as ' +str(request.user) )
        username=str(request.user)
        return username
    elif not request.user.is_authenticated:
        return None


#A request that creates a messages according to a provided 'payload' from user
@api_view(['POST'])
@permission_classes((AllowAny,))
def createmsg(request):
    output={}
    username=validateUser(request)
    try:
        # Params holds the payload and should be handled before parsing out the data
        params=ast.literal_eval(request.POST['params'])
    except:
        output['note'] = 'Params variables caused error'
        return Response(output, status=HTTP_400_BAD_REQUEST)
    # Validating if none of the variables are empty or missing
    try:
        if (params['receiver']==None or len(params['receiver'])<2) or (params['subject']==None or len(params['subject'])<2) or (params['content']==None or len(params['content'])<2):
            output['note'] = 'At least one of the variables seems to be empty, please recheck the variables'
            return Response(output, status=HTTP_400_BAD_REQUEST)
    except:
        output['note'] = 'Params variables caused error'
        return Response(output, status=HTTP_400_BAD_REQUEST)
    # If the user is connected, the process proceeds
    if username!=None:
        #Validates the reciever is not the sender
        if params['receiver']!=username:
            # Each message has two copies one for the 'outbox' and another one for the 'inbox'
            for i in range(0,2):
                message = Message()
                message.sender = username
                message.creation_date = timezone.now()
                message.receiver=params['receiver']
                message.subject=params['subject']
                message.message=params['content']
                if i==0:
                    message.status=1
                    message.inbox_mode='outbox'
                message.save()
            output['note'] = "Your message has been sent"
            return Response(output,status=HTTP_200_OK)
        else:
            output['note'] = 'Error - Same receiver and sender'
            return Response(output, status=HTTP_401_UNAUTHORIZED)
    else:
        output['note'] = 'User is unauthorized to perform this action'
        return Response(output,status=HTTP_401_UNAUTHORIZED)


#Show all messages of a specific user as a sender and a receiver
@api_view(['POST'])
@permission_classes((AllowAny,))
def showmsgs(request):
    output={}
    username=validateUser(request)
    print(username)
    if username!=None:
        result={}
        results=Message.objects.filter(Q(sender=username,inbox_mode='outbox') | Q(receiver=username,inbox_mode='inbox'))
        if len(results)>0:
            for i in range(0,len(results)):
                dict={}
                dict['receiver']=results[i].receiver
                dict['sender']=results[i].sender
                dict['subject']=results[i].subject
                dict['content']=results[i].message
                dict['creation_date']=results[i].creation_date
                result[str(i)]=dict
            output['result']=result
            output['note']='Found ' + str(len(results))+' Messages'
            return Response(output,status=HTTP_200_OK)
        else:
            output['note']='No messages'
            return Response(output, status=HTTP_200_OK)
    else:
        output['note'] = 'User is unauthorized to perform this action'
        return Response(output,status=HTTP_401_UNAUTHORIZED)


#Show all unread received messages of a specific user
@api_view(['POST'])
@permission_classes((AllowAny,))
def unreadmsgs(request):
    username=validateUser(request)
    output={}
    if username!=None:
        result={}
        results=Message.objects.filter(receiver=username,status=0,inbox_mode='inbox')
        if len(results) > 0:
            for i in range(0,len(results)):
                dict={}
                dict['receiver']=results[i].receiver
                dict['sender']=results[i].sender
                dict['subject']=results[i].subject
                dict['content']=results[i].message
                dict['creation_date']=results[i].creation_date
                result[str(i)]=dict
            output['result'] = result
            output['note'] = 'Found' + str(len(results)) + ' Messages'
            return Response(output,status=HTTP_200_OK)
        else:
            output['note']='No new unread messages'
            return Response(output, status=HTTP_200_OK)
    else:
        output['note'] = 'User is unauthorized to perform this action'
        return Response(output,status=HTTP_401_UNAUTHORIZED)


#A request which reads one message at a time. The message can be from an inbox or outbox.
#It also can be provided with an exact position of a message within an array of messages.
@api_view(['POST'])
@permission_classes((AllowAny,))
def readmsg(request):
    output={}
    username=validateUser(request)
    if username!=None:
        params_len=0
        results=Message.objects.filter(Q(receiver=username,inbox_mode='inbox') | Q(sender=username,inbox_mode='outbox'))
        #Checks if there are any messeges to present
        if len(results)>0:
            # If there are it will use the session variable to determine the current position within the array of messages
            # This will be helpful for later use when there would be a need for a position references
            if request.session['msgnum']==-1:
                i=request.session['msgnum']=0
            else:
                request.session['msgnum']+=1
                i=request.session['msgnum']
                if i==len(results)-1:
                    request.session['msgnum']=-1
            try:
                #Checks if the payload is readable
                params_len=len(request.POST['params'])
            except:
                params_len=0
            if params_len>0:
                try:
                    #If there's data in the payload it will try to derive the position and locate the specific message
                    #If fails, it will continue on with the subsequent order of messages
                    params=ast.literal_eval(request.POST['params'])
                    pos=params['pos']
                    dict = {}
                    dict['receiver'] = results[pos].receiver
                    dict['sender'] = results[pos].sender
                    dict['subject'] = results[pos].subject
                    dict['content'] = results[pos].message
                    dict['creation_date'] = results[pos].creation_date
                    request.session['msgnum'] = pos
                    if results[pos].status == 0:
                        Message.objects.filter(receiver=username, creation_date=results[pos].creation_date).update(status=1)
                    output['result']=dict
                    output['note']='Message number '+str(pos)
                    return Response(output, status=HTTP_200_OK)
                except:
                    output['note']="Please check position variable"
                    return Response(output, status=HTTP_400_BAD_REQUEST)
            else:
                dict={}
                dict['receiver']=results[i].receiver
                dict['sender']=results[i].sender
                dict['subject']=results[i].subject
                dict['content']=results[i].message
                dict['creation_date']=results[i].creation_date
                if results[i].status==0:
                    Message.objects.filter(receiver=username,creation_date=results[i].creation_date).update(status=1)
                output['result'] = dict
                output['note'] = 'Message number ' + str(i)
                return Response(output,status=HTTP_200_OK)
        else:
            output['note'] = "No messages"
            return Response(output, status=HTTP_200_OK)
    else:
        output['note'] = 'User is unauthorized to perform this action'
        return Response(output,status=HTTP_401_UNAUTHORIZED)


#A request that deletes a message by current position or provided position
@api_view(['POST'])
@permission_classes((AllowAny,))
def delmsg(request):
    output={}
    username = validateUser(request)
    if username != None:
        #The current position is determined by the 'session' variable
        currentmsg=request.session['msgnum']
        results = Message.objects.filter(Q(receiver=username,inbox_mode='inbox') | Q(sender=username,inbox_mode='outbox'))
        if len(results)>0:
            try:
                params_len=len(request.POST['params'])
            except:
                params_len=0
            if params_len>1:
                try:
                    #If there's a valid paylod it will try to locate the message
                    params = ast.literal_eval(request.POST['params'])
                    pos = int(params['pos'])
                    results[pos].delete()
                    request.session['msgnum']=pos-1
                    output['note'] = 'Deleted'
                    return Response(output, status=HTTP_200_OK)
                except:
                    # If fails, there would be an error - it won't delete any other messages
                    output['note']="There's no message at the provided position"
                    return Response(output, status=HTTP_400_BAD_REQUEST)
            else:
                #If there's no payload the message at the current postion will be deleted
                results[currentmsg].delete()
                request.session['msgnum']-=1
                output['note']='Deleted'
                return Response(output, status=HTTP_200_OK)
        else:
            output['note']='No messages to delete'
            return Response(output, status=HTTP_400_BAD_REQUEST)
    else:
        output['note'] = 'User is unauthorized to perform this action'
        return Response(output,status=HTTP_401_UNAUTHORIZED)




