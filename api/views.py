import logging

from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import permissions, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView as SimpleJWTRefreshView

from api.models import User
from api.serializers import AuthTokenSerializer, LoginSerializer, UserSerializer

logger = logging.getLogger(__name__)


# Create your views here.
@extend_schema(
    summary="Register a new user",
    tags=["Authentication"],
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
    name = 'RegisterView'
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


def set_refresh_cookie(response, refresh_token):
    response.set_cookie(
        key=settings.SIMPLE_JWT['AUTH_COOKIE'],
        value=refresh_token,
        httponly=True,
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path='/api/',  # giới hạn đường dẫn
        max_age=7 * 24 * 60 * 60  # 7 ngày
    )

class LoginView(APIView):
    serializer_class = LoginSerializer
    name = 'LoginView'

    @extend_schema(
        request=LoginSerializer,
        tags=['Authentication'],
        summary='Đăng nhập',
        responses={
            200: OpenApiResponse(AuthTokenSerializer, description='Đăng nhập thành công'),
            400: OpenApiResponse(description='Lỗi dữ liệu đầu vào'),
        }
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            user_serializer = UserSerializer(user) # Serialize trực tiếp user
            response_data = {
                'user': user_serializer.data,
                'accessToken': access_token,
                # 'refresh': str(refresh),
            }
            response = Response(response_data, status=status.HTTP_200_OK)
            set_refresh_cookie(response, str(refresh))

            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProtectedView(APIView):
    permission_classes = (IsAuthenticated,)
    name = 'ProtectedView'

    @extend_schema(
        responses={
            200: OpenApiResponse(description='Dữ liệu API được bảo vệ'),
            401: OpenApiResponse(description='Không được xác thực'),
        },
    )
    def get(self, request):
        content = {'message': 'API này chỉ dành cho người dùng đã xác thực.'}
        return Response(content)


@extend_schema(
    summary="Get user information",
    tags=["User"],
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
    name = 'UserInfoView'

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
            "time": timezone.now(),
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
    name = 'UpdateUserInfoView'

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
    name = 'RefreshTokenView'
    authentication_classes = []
    permission_classes = []
    # Không cần xác thực cho view này
    @extend_schema(
        responses={
            200: OpenApiResponse(AuthTokenSerializer, description='Làm mới token thành công'),
            401: OpenApiResponse(description='Refresh token không hợp lệ hoặc đã hết hạn'),
        },
        parameters=[
            OpenApiParameter(
                name='refreshToken',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.COOKIE,
                description='Refresh token được lưu trong cookie',
                required=True,
            ),
        ]
    )
    def post(self, request):
        refresh_token = request.COOKIES.get('refreshToken') or request.data.get('refreshToken')
        if not refresh_token:
            return Response({'error': 'Không tìm thấy refresh token trong cookie.'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            refresh = RefreshToken(refresh_token)
            access_token = str(refresh.access_token)
            user = refresh.user

            response_data = {
                'user': AuthTokenSerializer(user).data['user'],
                'accessToken': access_token,
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': 'Refresh token không hợp lệ hoặc đã hết hạn.'}, status=status.HTTP_401_UNAUTHORIZED)


class CustomTokenRefreshView(SimpleJWTRefreshView):
    permission_classes = [permissions.AllowAny]

    @extend_schema(
        responses={
            200: OpenApiResponse(description='Làm mới token thành công'),
            401: OpenApiResponse(description='Refresh token không hợp lệ hoặc đã hết hạn'),
        },
    )
    def post(self, request, *args, **kwargs):
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])

        if refresh_token is None:
            return Response({"detail": "No refresh token provided"}, status=status.HTTP_401_UNAUTHORIZED)

        # Thêm token vào request.data để DRF xử lý
        request.data['refresh'] = refresh_token
        response = super().post(request, *args, **kwargs)

        # Trả lại accessToken mới
        return Response({
            "accessToken": response.data['access']
        }, status=status.HTTP_200_OK)


class LogoutView(APIView):
    # permission_classes = (IsAuthenticated,)
    name = 'LogoutView'

    @extend_schema(
        responses={
            204: OpenApiResponse(description='Đăng xuất thành công (xóa cookie)'),
            401: OpenApiResponse(description='Không được xác thực'),
        },
    )
    def post(self, request):
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie('refreshToken')
        return response
