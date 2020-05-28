from django.db import models

#Defines a message object
class Message(models.Model):
    sender=models.CharField(max_length=250)
    receiver=models.CharField(max_length=250)
    message=models.CharField(max_length=5000)
    subject=models.CharField(max_length=200)
    creation_date=models.DateTimeField('creation_date')
    inbox_mode =models.CharField(max_length=100,default='inbox')
    status=models.BooleanField(default=0)