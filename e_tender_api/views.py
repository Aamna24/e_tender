from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.authentication import TokenAuthentication
from rest_framework import filters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from e_tender_api import serializers, models, permissions
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import generics, status
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from django.conf import settings
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from .serializers import LoginSerializer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from .utils import Util

class Register(generics.GenericAPIView):
    serializer_class = serializers.UserProfileSerializer
    permission_classes = [AllowAny]

    
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)  
        serializer.is_valid(raise_exception=True)
        serializer.save()  

        user_data = serializer.data

        user = models.UserProfile.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token
        current_site = get_current_site(request).domain
        relativeLink = reverse('email-verify')
        #absurl='http://'+current_site+relativeLink+"?token="+str(token)
        absurl='https://etenders.herokuapp.com/email-verify/'+"?token="+str(token)
        email_body = 'Hi '+user.organization_name+' Use link below to verify your email \n'+absurl
        data = {'email_body':email_body, 'to_email': user.email,'email_subject':'Verify your email'}
        Util.send_email(data)
        return Response(user_data,status=status.HTTP_201_CREATED)                                        

class VerifyEmail(generics.GenericAPIView):
    serializer_class = serializers.EmailVerificationSerializer

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token,settings.SECRET_KEY,algorithms='HS256')
            user = models.UserProfile.objects.get(id=payload['user_id'])

            if not user.is_verified:
                user.is_verified= True
                user.save()

            return Response({'email':'Successfully activated'},status=status.HTTP_200_OK)                                        

        except jwt.ExpiredSignatureError as identifier:
             return Response({'error':'Activation expired'},status=status.HTTP_400_BAD_REQUEST) 

class UserProfileViewSet(viewsets.ModelViewSet):
    """handle creating and updating profiles"""
    serializer_class = serializers.UserProfileSerializer
    queryset = models.UserProfile.objects.all()
    authentication_classes = (TokenAuthentication,)
    #permission_classes = (permissions.UpdateOwnProfile,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('organization_name', 'email',)
    def patch(self, request):
        """Handle removing an object"""
        return Response({'http_method': 'PATCH'})
    def destroy(self, request):
        """Handle removing an object"""
        return Response({'http_method': 'DELETE'})


class TenderViewSet(viewsets.ModelViewSet):
    """handle creating tender"""
    serializer_class = serializers.PublishTenderSerializer
    queryset = models.Tenders.objects.all()
    filter_backends = (filters.SearchFilter,)
    search_fields = ('category', 'region')

    def patch(self, request, pk=None):
        """Handle updating part of an object"""
        return Response({'http_method': 'PATCH'})

# add search fields by keywords category etc


class BidViewSet(viewsets.ModelViewSet):
    """handle creating tender"""
    serializer_class = serializers.PostBidSerializer
    queryset = models.Bid.objects.all()
    filter_backends = (filters.SearchFilter,)
    search_fields = ('bidding_amount', 'tenderId')

    def patch(self, request, pk=None):
        """Handle updating part of an object"""
        return Response({'http_method': 'PATCH'})


class UserLoginApiView(ObtainAuthToken):
    """Handle creating user authentication tokens"""
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'organization': user.organization_name,
            'email': user.email
        })

class LoginAPIView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request):
        
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class RequestPasswordResetEmail(generics.GenericAPIView):
    serializer_class = serializers.ResetPasswordEmailRequestSerializer
    def post(self, request):
        #data = {'request':request, 'data':request.data}
        serializer = self.serializer_class(data=request.data)
        email = request.data['email']

        if models.UserProfile.objects.filter(email=email).exists():
                user = models.UserProfile.objects.get(email=email)
                uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
                token = PasswordResetTokenGenerator().make_token(user)
                current_site = get_current_site(request=request).domain
                relativeLink = reverse('password-reset-confirm',kwargs={'uidb64':uidb64,'token':token})
                #absurl='http://'+current_site + relativeLink
                absurl='https://etenders.herokuapp.com'+"/password-reset/"+uidb64+"/"+token
                email_body = 'Hello, \n  Use link below to reset your password \n'+absurl
                data = {'email_body':email_body, 'to_email': user.email,'email_subject':'reset your password'}
                Util.send_email(data) 
        return Response({'success':'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)

class PasswordtokenCheckAPI(generics.GenericAPIView):
    serializer_class= serializers.SetNewPasswordSerializer

    def get(self,request,uidb64,token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = models.UserProfile.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':' Token is not valid, please request a new one'}, status= status.HTTP_400_BAD_REQUEST)

            return Response({'success': True, 'message':'Credentials valid','uidb64':uidb64,'token':token}, status=status.HTTP_200_OK)


            
        except DjangoUnicodeDecodeError as identifier:
            return Response({'error':' Token is not valid, please request a new one'}, status= status.HTTP_400_BAD_REQUEST)


class SetNewPassword(generics.GenericAPIView):
    serializer_class = serializers.SetNewPasswordSerializer

    def patch(self, request, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success':True,'message':'Password reset success'}, status=status.HTTP_200_OK)
