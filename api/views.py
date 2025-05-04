import logging
from datetime import datetime, timedelta

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
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView as SimpleJWTRefreshView

from api.models import User
from api.serializers import (
    AuthTokenSerializer,
    FormSearchResultSerializer,
    LoginSerializer,
    SelectOptionSerializer,
    UserSerializer,
)

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
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

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
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT.get('AUTH_COOKIE_PATH', '/'),
        domain=settings.SIMPLE_JWT.get('AUTH_COOKIE_DOMAIN', None),
        max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()
    )

class LoginView(APIView):
    serializer_class = LoginSerializer
    name = 'LoginView'
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

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
                required=False,
            ),
        ]
    )
    def post(self, request):
        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) or request.data.get('refreshToken')
        if not refresh_token:
            print("refresh_token ", refresh_token)
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
    serializer_class = TokenRefreshSerializer  # ✅ THÊM DÒNG NÀY
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get_serializer(self, *args, **kwargs):
        refresh_token = self.request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE'])

        if not refresh_token:
            raise InvalidToken("No refresh token provided")

        kwargs['data'] = {'refresh': refresh_token}
        return self.serializer_class(*args, **kwargs)

    @extend_schema(
        responses={
            200: OpenApiResponse(description='Làm mới token thành công'),
            401: OpenApiResponse(description='Refresh token không hợp lệ hoặc đã hết hạn'),
            500: OpenApiResponse(description='Refresh token không hợp lệ hoặc đã hết hạn'),
        },
    )
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer()
        try:
            serializer.is_valid(raise_exception=True)
        except InvalidToken:
            return Response({"detail": "Refresh token không hợp lệ hoặc hết hạn"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({
            "accessToken": serializer.validated_data['access']
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


class FormSearchView(APIView):
    @extend_schema(
        parameters=[
            OpenApiParameter("page", int, required=False),
            OpenApiParameter("pageSize", int, required=False),
            OpenApiParameter("application_no", str, required=False),
            OpenApiParameter("title", str, required=False),
            OpenApiParameter("status", str, required=False),
            OpenApiParameter("manager", str, required=False),
            OpenApiParameter("customer_code", str, required=False),
            OpenApiParameter("register_date_start", str, required=False, description="yyyy-mm-dd"),
            OpenApiParameter("register_date_end", str, required=False, description="yyyy-mm-dd"),
            OpenApiParameter("category", str, required=False),
        ],
        responses=FormSearchResultSerializer(many=True)
    )
    def get(self, request):
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("pageSize", 10))
        query = request.GET

        # Sinh dữ liệu mẫu
        all_data = []
        for i in range(1, 201):
            all_data.append({
                "id": i,
                "application_no": f"APP-{i:04}",
                "title": f"Tiêu đề {i}",
                "status": "approved" if i % 2 == 0 else "pending",
                "manager": f"manager{i % 3 + 1}",
                "customer_code": f"customer{i % 5 + 1}",
                "register_date": (datetime.now() - timedelta(days=i)).date(),
                "category": f"category{i % 2 + 1}"
            })

        # Lọc theo params
        def match_filter(item):
            if "application_no" in query and query["application_no"] and query["application_no"] not in item["application_no"]:
                return False
            if "title" in query and query["title"] and query["title"].lower() not in item["title"].lower():
                return False
            if "status" in query and query["status"] and item["status"] != query["status"]:
                return False
            if "manager" in query and query["manager"] and item["manager"] != query["manager"]:
                return False
            if "customer_code" in query and query["customer_code"] and item["customer_code"] != query["customer_code"]:
                return False
            if "category" in query and query["category"] and item["category"] != query["category"]:
                return False
            if "register_date_start" in query and "register_date_end" in query:
                start = datetime.strptime(query["register_date_start"], "%Y-%m-%d").date()
                end = datetime.strptime(query["register_date_end"], "%Y-%m-%d").date()
                if not (start <= item["register_date"] <= end):
                    return False
            return True

        filtered_data = list(filter(match_filter, all_data))
        record_total = len(all_data)
        record_filtered = len(filtered_data)

        start = (page - 1) * page_size
        end = start + page_size
        paginated_data = filtered_data[start:end]

        serializer = FormSearchResultSerializer(paginated_data, many=True)
        return Response({
            "data": serializer.data,
            "page": page,
            "pageSize": page_size,
            "recordTotal": record_filtered,   # Số lượng sau khi lọc, dùng cho phân trang thực tế
            "recordAll": record_total         # Tổng số bản ghi trước lọc (nếu cần hiển thị)
        })



class FormSelectsView(APIView):
    @extend_schema(
        parameters=[
            OpenApiParameter("field", str, required=True),
            OpenApiParameter("search", str, required=False),
            OpenApiParameter("page", int, required=False),
            OpenApiParameter("pageSize", int, required=False),
        ],
        responses=SelectOptionSerializer(many=True)
    )
    def get(self, request):
        field = request.GET.get("field")
        search = request.GET.get("search", "").lower()
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("pageSize", 10))

        match field:
            case "application_no":
                options = [{"label": f"APP-{i:04}", "value": f"APP-{i:04}"} for i in range(1, 201)]
            case "manager":
                options = [{"label": f"Quản lý {i}", "value": f"manager{i}"} for i in range(1, 4)]
            case "customer_code":
                options = [{"label": f"Khách hàng {i}", "value": f"customer{i}"} for i in range(1, 4)]
            case "category":
                options = [{"label": f"Loại {i}", "value": f"category{i}"} for i in range(1, 4)]
            case "status":
                options = [
                    {"label": "Đã duyệt", "value": "approved"},
                    {"label": "Đang chờ", "value": "pending"},
                ]
            case _:
                options = []

        # Lọc search
        if search:
            options = [opt for opt in options if search in opt["label"].lower()]

        total = len(options)
        start = (page - 1) * page_size
        end = start + page_size
        paginated = options[start:end]

        serializer = SelectOptionSerializer(paginated, many=True)
        return Response({
            "data": serializer.data,
            "currentPage": page,
            "totalPages": (total + page_size - 1) // page_size
        })
