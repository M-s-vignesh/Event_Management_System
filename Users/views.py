from django.shortcuts import render
from rest_framework import generics,viewsets
from .models import User
from .serializers import UserSerializer
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.exceptions import PermissionDenied
from rest_framework.authentication import TokenAuthentication
from rest_framework.response import Response
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.parsers import FormParser,MultiPartParser
from drf_yasg.utils import swagger_auto_schema
from rest_framework.authtoken.views import obtain_auth_token
from rest_framework.decorators import( 
                api_view, 
                parser_classes, 
                permission_classes,
                )
from rest_framework.permissions import AllowAny
from django.contrib.auth import authenticate
from drf_yasg import openapi


# Create your views here.
@swagger_auto_schema(
    method='post',
    manual_parameters=[
        openapi.Parameter('username', openapi.IN_FORM, description="Username", type=openapi.TYPE_STRING, required=True),
        openapi.Parameter('password', openapi.IN_FORM, description="Password", type=openapi.TYPE_STRING, required=True),
    ],
    responses={200: "Token"},
)
@api_view(['POST'])
@permission_classes([AllowAny])
def obtain_auth_token_form(request):
    """
    Custom view to obtain authentication token using a FORM-based input.
    """
    username = request.POST.get('username')
    password = request.POST.get('password')

    if not username or not password:
        return Response({"error": "Please provide both username and password."}, status=status.HTTP_400_BAD_REQUEST)

    user = authenticate(username=username, password=password)
    if user:
        token, created = Token.objects.get_or_create(user=user)
        return Response({"token": token.key})
    
    return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class UserListView(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    parser_classes =[MultiPartParser, FormParser]

    def get_queryset(self):
        if self.request.user.is_superuser:
            return User.objects.all()
        return User.objects.filter(id=self.request.user.id)
    
    @swagger_auto_schema(request_body=UserSerializer)
    def create(self, request, *args, **kwargs):
        if not request.user.is_superuser:
            return Response({"detail": "You don't have access to create a account."}, status= status.HTTP_403_FORBIDDEN)
        return super().create(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        user = self.get_object()
        if not request.user.is_superuser and user.id != request.user.id:
            raise PermissionDenied("You don't have access")
        serializer = self.get_serializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    @swagger_auto_schema(request_body=UserSerializer)
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        if not request.user.is_superuser and user.id != request.user.id:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(user, data=request.data)
        serializer.is_valid(raise_exception = True)
        self.perform_update(serializer)
        return Response(serializer.data, status = status.HTTP_200_OK)
    
    @swagger_auto_schema(request_body=UserSerializer)
    def partial_update(self, request, *args, **kwargs):
        user = self.get_object()
        if not request.user.is_superuser and request.user.id != user.id:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        serializer = self.get_serializer(user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema()
    def destroy(self, request, *args, **kwargs):
        user = self.get_object()
        if not request.user.is_superuser and request.user.id !=user.id:
            return Response({"detail": "You don't have access to delete this account"}, status=status.HTTP_403_FORBIDDEN)
        Token.objects.filter(user=user).delete()
        return super().destroy(request, *args, **kwargs)
    


