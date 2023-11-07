from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.shortcuts import render
from rest_framework import generics
from rest_framework.exceptions import AuthenticationFailed
import requests
from requests.auth import HTTPBasicAuth
from .models import CustomUser
from .serializers import UserSerializer
from django.contrib.auth import get_user_model
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import JSONRenderer
from rest_framework.authentication import TokenAuthentication

# User Signup View
class UserSignupView(generics.CreateAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        response = super(UserSignupView, self).post(request, *args, **kwargs)
        user = get_user_model().objects.get(email=request.data['email'])
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key}, status=status.HTTP_201_CREATED)

# User Login View
class UserLoginView(APIView):
    # This view will not require authentication
    def post(self, request, *args, **kwargs):
        renderer_classes = [JSONRenderer]
        requests.packages.urllib3.disable_warnings()
        email = request.data.get("email")
        password = request.data.get("password")
        user = authenticate(request, username=email, password=password)
        if user is not None:
            token, created = Token.objects.get_or_create(user=user)
            return Response({"token": token.key}, status=status.HTTP_200_OK)
        elif user is None:
            return Response({"error": "Incorrect login info"}, status=status.HTTP_401_UNAUTHORIZED)
        elif not user.check_password(password):
            return Response({"error": "Incorrect password"}, status=status.HTTP_401_UNAUTHORIZED)

class UserView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # The request.user will be set to the authenticated CustomUser instance
        serializer = UserSerializer(request.user)
        return Response(serializer.data)

class UserRetrieveView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        # Assuming the user is already authenticated and you want to retrieve their information
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)

class LogoutView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # This removes the authentication token and thus logs the user out
        request.user.auth_token.delete()
        return Response({"message": "You're logged out"},status=204)


class PasswordResetRequestView(APIView):
    def post(self, request, *args, **kwargs):
        email = request.data.get('email')
        user = get_user_model().objects.filter(email=email).first()
        if user:
            token = default_token_generator.make_token(user)
            # Build password reset URL with token
            reset_url = f'https://10.10.61.58:8000/resepw?token={token}&email={email}'
            # Send email to user with this reset URL
            send_mail(
                'Password Reset Request',
                f'Please click the link to reset your password: {reset_url}',
                'email',
                [email],
                fail_silently=False,
            )
        return Response({'message': 'If an account with that email exists, we have sent an email with password reset instructions'}, status=status.HTTP_200_OK)