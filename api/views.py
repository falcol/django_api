import logging

from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)


# Create your views here.
@extend_schema(
    summary="Register a new user",
    description="Registers a new user with a username and password. Returns JWT tokens upon success.",
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": ["username", "password"],
        }
    },
    responses={
        201: {
            "type": "object",
            "properties": {
                "refresh": {"type": "string"},
                "access": {"type": "string"},
            },
        },
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
)
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


@extend_schema(
    summary="Login a user",
    description="Authenticates a user with a username and password. Returns JWT tokens upon success.",
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "password": {"type": "string"},
            },
            "required": ["username", "password"],
        }
    },
    responses={
        200: {
            "type": "object",
            "properties": {
                "refresh": {"type": "string"},
                "access": {"type": "string"},
            },
        },
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
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


@extend_schema(
    summary="Access a protected view",
    description="Returns a message if the user is authenticated.",
    responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
)
class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "This is a protected view"})


@extend_schema(
    summary="Get user information",
    description="Returns the authenticated user's information.",
    responses={
        200: {
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "email": {"type": "string"},
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "date_joined": {"type": "string", "format": "date-time"},
                "last_login": {"type": "string", "format": "date-time"},
                "is_active": {"type": "boolean"},
            },
        }
    },
)
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
            "is_active": user.is_active,
        }
        return Response(user_info)


@extend_schema(
    summary="Update user information",
    description="Updates the authenticated user's information. Optionally updates the password.",
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "email": {"type": "string"},
                "first_name": {"type": "string"},
                "last_name": {"type": "string"},
                "password": {"type": "string"},
            },
        }
    },
    responses={
        200: {"type": "object", "properties": {"message": {"type": "string"}}},
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
)
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


@extend_schema(
    summary="Refresh access token",
    description="Generates a new access token using a refresh token.",
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "refresh": {"type": "string"},
            },
            "required": ["refresh"],
        }
    },
    responses={
        200: {"type": "object", "properties": {"access": {"type": "string"}}},
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
)
class RefreshTokenView(APIView):
    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        if refresh_token is None:
            return Response({"error": "Refresh token is required"}, status=400)

        try:
            refresh = RefreshToken(refresh_token)
            new_access_token = refresh.access_token
            return Response({"access_token": str(new_access_token)})
        except Exception as e:
            return Response({"error": str(e)}, status=400)


@extend_schema(
    summary="Logout a user",
    description="Blacklists the provided refresh token to log out the user.",
    request={
        "application/json": {
            "type": "object",
            "properties": {
                "refresh": {"type": "string"},
            },
            "required": ["refresh"],
        }
    },
    responses={
        200: {"type": "object", "properties": {"message": {"type": "string"}}},
        400: {"type": "object", "properties": {"error": {"type": "string"}}},
    },
)
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
            return Response({"error": str(e)}, status=400)
