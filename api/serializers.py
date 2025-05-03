from django.contrib.auth import authenticate
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'username', 'email') # Thêm các trường bạn muốn trả về

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if not user.is_active:
                    raise serializers.ValidationError('Tài khoản bị vô hiệu hóa.')
                return user
            else:
                raise serializers.ValidationError('Sai thông tin đăng nhập.')
        else:
            raise serializers.ValidationError('Vui lòng nhập cả tên đăng nhập và mật khẩu.')

class AuthTokenSerializer(serializers.Serializer):
    user = UserSerializer(read_only=True)
    accessToken = serializers.CharField(read_only=True)
    refreshToken = serializers.CharField(read_only=True)

class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()
    access = serializers.CharField(read_only=True)

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def create(self, validated_data):
        try:
            refresh = RefreshToken(self.token)
        except TokenError as e:
            raise serializers.ValidationError(str(e))

        return {'access': str(refresh.access_token)}


class FormSearchResultSerializer(serializers.Serializer):
    id = serializers.IntegerField(help_text="ID đơn đăng ký")
    application_no = serializers.CharField(help_text="Số đơn đăng ký")
    title = serializers.CharField(help_text="Tiêu đề đơn đăng ký")
    status = serializers.CharField(help_text="Trạng thái xử lý")
    manager = serializers.CharField(help_text="Người phụ trách xử lý")
    customer_code = serializers.CharField(help_text="Mã khách hàng")
    register_date = serializers.DateField(help_text="Ngày đăng ký")
    category = serializers.CharField(help_text="Phân loại hồ sơ")



class SelectOptionSerializer(serializers.Serializer):
    label = serializers.CharField()
    value = serializers.CharField()
