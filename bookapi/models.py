from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class Books(models.Model):
    title = models.CharField(max_length=255, null=False)
    author = models.CharField(max_length=255, null=False)
    available_copies = models.IntegerField()
    users_lended = models.ManyToManyField(User, blank=True)

    def __str__(self):
        return self.title

