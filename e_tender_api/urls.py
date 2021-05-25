from django.urls import path, include
from rest_framework.routers import DefaultRouter
from e_tender_api import views

router = DefaultRouter()
router.register('profile', views.UserProfileViewSet)
router.register('publish-tender', views.TenderViewSet)
router.register('bid', views.BidViewSet)


urlpatterns = [
    path('login/', views.UserLoginApiView.as_view()),
    path('', include(router.urls)),
    path('api-auth/', include('rest_framework.urls'))

]
