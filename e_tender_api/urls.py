from django.urls import path, include
from rest_framework.routers import DefaultRouter
from e_tender_api import views

router = DefaultRouter()
router.register('profile', views.UserProfileViewSet)
router.register('publish-tender', views.TenderViewSet)
router.register('bid', views.BidViewSet)


urlpatterns = [
   # path('login/', views.UserLoginApiView.as_view()),
    path('', include(router.urls)),
    path('login/', views.LoginAPIView.as_view(), name="login"),
    path("register/", views.Register.as_view(), name="register"),
    path("email-verify/", views.VerifyEmail.as_view(), name="email-verify"),
    path('api-auth/', include('rest_framework.urls')),
    path('request-reset-email/', views.RequestPasswordResetEmail.as_view(), name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/',views.PasswordtokenCheckAPI.as_view(), name='password-reset-confirm'),
    path('password-reset-complete/<uidb64>/<token>/',views.SetNewPassword.as_view(), name='password-reset-complete')

]
