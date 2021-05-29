from rest_framework import serializers
from e_tender_api import models
from django.http import HttpRequest
import json
from rest_framework.response import Response
from .models import UserProfile
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import send_mail


class HelloSerializer(serializers.Serializer):
    """Serializes a name field for testing our API view"""
    name = serializers.CharField(max_length=10)


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

    def create(self, validated_data):
        """Create and return a new user"""
        user = models.UserProfile.objects.create_user(

            organization_name=validated_data['organization_name'],
            password=validated_data['password'],
            email=validated_data['email'],
            ntn=validated_data['ntn'],
            contact=validated_data['contact'],
            address=validated_data['address'],
        )
        return user

    def update(self, instance, validated_data):
        """Handle updating user account"""
        if 'password' in validated_data:
            password = validated_data.pop('password')
            instance.set_password(password)

        return super().update(instance, validated_data)


class ProfileFeeditemSerializer(serializers.ModelSerializer):
    """Serializers profile feed itmes"""
    class Meta:
        model = models.ProfileFeedItem
        fields = ('id', 'user_profile', 'status_text', 'created_on')
        extra_kwargs = {
            'user_profile': {'read_only': True}
        }


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
                  'contact', 'tenderId', 'title', 'file_uploaded', 'postedBy', 'status')

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

        )

        bid.save()
        mail_subject = 'Tender Published'
        message = 'Your bid has been placed on Tender Title'
        to_email = 'aamna.majid@gmail.com'
        send_mail(mail_subject, json.dumps(message),
                  "fa17-bcs-081@cuilahore.edu.pk", [to_email])
        return bid
