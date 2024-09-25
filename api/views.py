from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils import timezone
import logging

logger = logging.getLogger(__name__)


# Create your views here.
class RegisterView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        # Check if username or password is missing
        if not username:
            return Response({"error": "Username is required"}, status=400)
        if not password:
            return Response({"error": "Password is required"}, status=400)

        # Check if the username already exists
        if User.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=400)

        try:
            # Validate password strength
            validate_password(password)

            # Create the user
            user = User.objects.create_user(username=username, password=password)

            # Generate JWT tokens for the user
            refresh = RefreshToken.for_user(user)

            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                status=201,
            )

        except ValidationError as ve:
            # Password didn't pass the validation
            return Response({"error": ve.messages}, status=400)

        except Exception as e:
            # Log the exception for debugging purposes
            logger.error(f"Error during user registration: {e}")
            return Response(
                {"error": "An unexpected error occurred. Please try again later."},
                status=500,
            )


class LoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if user is not None:
            # Update last login
            user.last_login = timezone.now()
            user.save()

            refresh = RefreshToken.for_user(user)
            return Response(
                {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            )
        return Response({"error": "Invalid Credentials"}, status=400)


class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "This is a protected view"})


class UserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user: User = request.user
        user_info = {
            "username": user.username,
            "email": user.email,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "date_joined": user.date_joined,
            "last_login": user.last_login,
        }
        return Response(user_info)


class UpdateUserInfoView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request):
        user: User = request.user
        data: dict = request.data

        # Update user fields
        user.email = data.get("email", user.email)
        user.first_name = data.get("first_name", user.first_name)
        user.last_name = data.get("last_name", user.last_name)

        # Validate password if provided
        password = data.get("password")
        if password:
            try:
                validate_password(password, user)
                user.set_password(password)
            except ValidationError as ve:
                return Response({"error": ve.messages}, status=400)

        try:
            user.save()
            return Response({"message": "User info updated successfully"})
        except Exception as e:
            logger.error(f"Error updating user info: {e}")
            return Response(
                {"error": "An unexpected error occurred. Please try again later."},
                status=500,
            )


class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh")
        if refresh_token is None:
            return Response({"error": "Refresh token is required"}, status=400)

        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = refresh.access_token
            return Response({"access": str(new_access_token)})
        except Exception as e:
            return Response({"error": str(e)}, status=400)


class LogoutView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh")
        if refresh_token is None:
            return Response({"error": "Refresh token is required"}, status=400)

        try:
            refresh = RefreshToken(refresh_token)
            refresh.blacklist()
            return Response({"message": "Logout successful"})
        except Exception as e:
            return Response({"error": str(e)}, status=400)  # noqa
