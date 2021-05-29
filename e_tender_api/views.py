from rest_framework.response import Response
from rest_framework import viewsets
from rest_framework.authentication import TokenAuthentication
from rest_framework import filters
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from e_tender_api import serializers, models, permissions
from django.contrib.auth import authenticate, login, logout
from rest_framework.authtoken.models import Token


class UserProfileViewSet(viewsets.ModelViewSet):
    """handle creating and updating profiles"""
    serializer_class = serializers.UserProfileSerializer
    queryset = models.UserProfile.objects.all()
    authentication_classes = (TokenAuthentication,)
    permission_classes = (permissions.UpdateOwnProfile,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('organization_name', 'email',)

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
