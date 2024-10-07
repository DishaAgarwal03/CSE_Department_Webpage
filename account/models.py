from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class User(AbstractUser):
    is_admin = models.BooleanField('Is admin', default=False)
    is_student = models.BooleanField('Is student', default=False)
    is_teacher = models.BooleanField('Is teacher', default=False)

class Document(models.Model):
    file = models.FileField(upload_to='documents/')
    name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)

class Courses(models.Model):
    class Meta:
        ordering = ['cname']
    cname = models.CharField(max_length=255)
    c_code = models.IntegerField()
    cred = models.IntegerField()

class Pubs(models.Model):
    class Meta:
        ordering = ['auth']
    auth = models.CharField(max_length=1024)
    pub_title = models.CharField(max_length=255)
    topic = models.CharField(max_length=255)
    pub_date = models.DateField()


