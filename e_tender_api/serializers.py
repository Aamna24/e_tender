from rest_framework import serializers
from e_tender_api import models
from django.http import HttpRequest
import json
from rest_framework.response import Response
from .models import UserProfile
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail
from django.contrib import auth
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util





class PublishTenderSerializer(serializers.ModelSerializer):
    """Serializes a tender object"""
    class Meta:
        model = models.Tenders
        fields = ('id', 'organization_name', 'category', 'title', 'availibility', 'region',
                  'description', 'contact', 'opening_date', 'last_date', 'datepublished', 'file_uploaded', 'email', 'assigned_to')

    def create(self, validated_data):
        request = self.context.get('request')

        tender = models.Tenders(
            organization_name=validated_data['organization_name'],
            title=validated_data['title'],
            availibility=validated_data['availibility'],
            category=validated_data['category'],
            region=validated_data['region'],
            description=validated_data['description'],
            contact=validated_data['contact'],
            opening_date=validated_data['opening_date'],
            last_date=validated_data['last_date'],
            email=validated_data['email'],
            assigned_to=validated_data['assigned_to'],
            file_uploaded=request.FILES.get('file_uploaded', default=''),


        )
        email = request.data['email']
        tender.save()
        mail_subject = 'Tender Published'
        message = 'Thank you for publishing your tender'
        to_email = email
        send_mail(mail_subject, json.dumps(message),
                  "maamna24@gmail.com", [to_email])
        return tender


class PostBidSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Bid
        fields = ('id', 'name', 'no_of_days', 'bidding_amount',
                  'contact', 'tenderId', 'title', 'file_uploaded', 'postedBy', 'status','email')

    def create(self, validated_data):
        request = self.context.get('request')

        bid = models.Bid(
            name=validated_data['name'],
            contact=validated_data['contact'],
            no_of_days=validated_data['no_of_days'],
            bidding_amount=validated_data['bidding_amount'],
            tenderId=validated_data['tenderId'],
            title=validated_data['title'],
            file_uploaded=request.FILES.get('file_uploaded', default=''),
            postedBy=validated_data['postedBy'],
            status=validated_data['status'],
            email=validated_data['email'],

        )
        email = request.data['email']
        title = request.data['title']

        bid.save()

        mail_subject = 'Bid Placed'
        message = 'Your bid has been placed on Tender Title '+title
        to_email = email
        send_mail(mail_subject, json.dumps(message),
                  "maamna24@gmail.com", [to_email])
        return bid


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = models.UserProfile
        fields=['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=10, min_length=4, write_only=True)
    organization_name= serializers.CharField(max_length=255,min_length=4,read_only=True)
    tokens = serializers.CharField(max_length=255,min_length=4,read_only=True)
    class Meta:
        model = models.UserProfile
        fields = ['email','password','organization_name','tokens']
  
    def validate(self, attrs):
        email = attrs.get('email','')
        password = attrs.get('password','')

        user = auth.authenticate(email = email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')

        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:  
            raise AuthenticationFailed('Email Verification required')

        print("token is",user.tokens)
        
        return {
            'email':user.email,
            'organization_name':user.organization_name,
            'tokens':user.tokens
        }
        
        return super().validate(attrs)

class UserProfileSerializer(serializers.ModelSerializer):
    """Serializes a user profile object"""

    class Meta:
        model = models.UserProfile
        fields = ('id', 'organization_name', 'email',
                  'password', 'ntn', 'contact', 'address')
        extra_kwargs = {
            'password': {
                'write_only': True,
                'style': {"input_type": 'password'}
            }
        }

    

    def validate(self, attrs):
        email = attrs.get('email','')
        organization_name = attrs.get('organization_name', '')
        contact = attrs.get('contact', '')
        address = attrs.get('address', '')
        ntn = attrs.get('ntn', '')

        return attrs
    def create(self, validated_data):
        return models.UserProfile.objects.create_user(**validated_data)



class ResetPasswordEmailRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=80)

    class Meta:
        fields=['email']

class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68,write_only=True)
    token = serializers.CharField(min_length=1,write_only=True)
    uidb64 = serializers.CharField(min_length=1,write_only=True)

    class Meta:
        fields=['password','token','uidb64']
    
    def validate(self, attrs):
        try:
            password=attrs.get('password')
            token = attrs.get('token')
            uidb64=attrs.get('uidb64')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = models.UserProfile.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed('The reset link is invalid', 401)
            
            user.set_password(password)
            user.save()

            return(user)
        
        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid', 401)

        return super().validate(attrs)
    
    