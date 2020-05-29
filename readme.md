# Mailedit API - Message Handler
### Here is a brief overview of the API  and its requests.   

## Overview
The API handles messages between two parties (a sender and a receiver).
There are in total 7 requests that control each action of the user over the api:
Login/Logout, compose a message, read a message ,and delete a message.  
Each recipient has its own copy which prevents data loss in case one of the parties deletes the message. 
The API is  a token-based authentication, which means that after the user being identified, it provided with
a unique token for each session instead of the transmission of a complicated cookie between a client and a backend. 

## Requests

### Login
Validates and authenticates the credentials of a user.
The request is supplied with username and password within its 'body'. 
After successfully logging in a new token will be assigned - there's a code snippet in Postman that should also copy the token
 into an environment variable.

### Logout
Signing off a user from the system. 
After logging out the token will be removed. 

### createmsg
Composing a new message by data provided by a 'payload'.
The payload contains all the required elements of a message.
The 'payload' is passed within the body of the request as well. 

### showmsgs
It provides a list of all the messages of a specific user as a sender and a receiver.
It doesn't require any parameters or arguments from the user.

### unreadmsgs
A request that provides a list of all the unread messages of a specific user as a sender and a receiver.
It doesn't require any parameters or arguments from the user.

### readmsg
The request provides one message at a time, going through the message of a specific user as a sender and a receiver. If it encounters an 'unread' message it will turn into a 'read' message. The request can also be provided with a position variable - if the position is valid the message at a specific position will be displayed. Please note that the request cycle the messages endlessly.   

### delmsg
The request allowing the user to delete a message. There are two methods to delete a message:
1. Delete message at the current position from 'readmsg' request  - using a session variable that holds that current position of a message
2. Delete message at a specific position - getting a position within the request's body. If the position is valid the message got deleted

## Postman
The postman JSON file has been also uploaded to this git as well. 
The name of the file is 'API_Test.postman_collection.json'. 
Please also add the variable 'token' to your environment (otherwise, things might not work properly). Init and current values should be set to 0/null. 




