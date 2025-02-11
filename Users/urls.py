from django.urls import path,include
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions,routers
from  Users.views import UserListView
from rest_framework.authentication import TokenAuthentication, BasicAuthentication, SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authtoken.views import obtain_auth_token
from .views import obtain_auth_token_form

router = routers.DefaultRouter()
router.register(r'users',UserListView, basename='user')

schema_view = get_schema_view(
    openapi.Info(
        title="User API",
        default_version='v1',
        description="API for managing custom user data",
        contact=openapi.Contact(email="admin@example.com"),
    ),
    public=True,
    permission_classes=(AllowAny,),
    authentication_classes=(),
)

urlpatterns = [
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('api-token-auth/', obtain_auth_token),
    path('',include(router.urls)),
]
