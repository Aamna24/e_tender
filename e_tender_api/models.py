from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.models import BaseUserManager
from django.conf import settings
from django.utils.timezone import now
from datetime import datetime


class UserProfileManager(BaseUserManager):
    """Manager for user profiles"""

    def create_user(self, organization_name, email, password=None, **extra_fields):
        """
        Create and save a User with the given email and password.
        """
        if not organization_name:
            raise ValueError('Organization Name is no correct')

        email = self.normalize_email(email)
        user = self.model(organization_name=organization_name,
                          email=email, **extra_fields)

        user.set_password(password)
        user.save(using=self._db)

        return user

    def create_superuser(self, organization_name, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        user = self.create_user(organization_name, email,
                                password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)

        return user


class UserProfile(AbstractBaseUser, PermissionsMixin):
    """Database model for users in the system"""
    email = models.EmailField(max_length=255, unique=True)
    organization_name = models.CharField(max_length=255, unique=True)
    # password=models.CharField(max_length=250,default='')
    ntn = models.CharField(max_length=15, unique=True)
    address = models.CharField(max_length=100)
    contact = PhoneNumberField(blank=False, null=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserProfileManager()

    """overriding username field"""
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['organization_name']

    def get_full_name(self):
        """Retrieve full name of users"""
        return self.organization_name

    def get_short_name(self):
        """Retrieve short name of users"""
        return self.organization_name

    def __str__(self):
        """Return string representation of user"""
        return self.email


class Tenders(models.Model):
    """Database model for Tenders in system"""

    status_option = {
        ('active', 'Active'),
        ('inactive', 'Inactive')
    }

    category_option = {
        ('construction', 'Construction'),
        ('medical', 'Medical'),
        ('electrical', 'Electrical'),
        ('it', 'IT'),
        ('telecom', 'Telecom'),
        ('oil and gas', 'Oil and Gas'),
        ('others', 'Others')
    }
    category = models.CharField(
        max_length=100, default='Construction', blank=False)
    organization_name = models.CharField(
        max_length=100, default='', blank=False)
    title = models.CharField(max_length=100, default='', blank=False)
    availibility = models.CharField(
        max_length=10, default="active", blank=False)
    region = models.CharField(max_length=20, default='', blank=False)
    description = models.TextField(default='', blank=False)
    contact = PhoneNumberField(blank=False, null=True, default=0)
    opening_date = models.DateField(default='')
    last_date = models.DateField(default='')
    datepublished = models.DateField(auto_now_add=True)
    email = models.EmailField(max_length=255, default='')
    file_uploaded = models.FileField(upload_to='uploads', default='')


class ProfileFeedItem(models.Model):
    """Profile status update"""
    user_profile = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE
    )
    status_text = models.CharField(max_length=255)
    created_on = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        """Return a model as a string"""
        return self.status_text


class Bid(models.Model):
    name = models.CharField(max_length=50, default="")
    no_of_days = models.IntegerField(default=0)
    bidding_amount = models.IntegerField(default=0)
    contact = PhoneNumberField(blank=False, null=True, default=0)
    tenderId = models.IntegerField(default=0)
    title = models.CharField(max_length=255, default="")
    file_uploaded = models.FileField(upload_to='uploads', default='')
    postedBy = models.CharField(max_length=50, default="")
    status = models.CharField(max_length=50, default="")
