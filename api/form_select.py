from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import serializers
from drf_spectacular.utils import extend_schema, OpenApiParameter


class SelectOptionSerializer(serializers.Serializer):
    label = serializers.CharField()
    value = serializers.CharField()


class SelectResponseSerializer(serializers.Serializer):
    data = SelectOptionSerializer(many=True)
    currentPage = serializers.IntegerField()
    totalPages = serializers.IntegerField()


class BatchSelectRequestSerializer(serializers.Serializer):
    fields = serializers.ListField(child=serializers.CharField())
    search = serializers.CharField(required=False, allow_blank=True, default="")
    page = serializers.IntegerField(required=False, default=1)
    pageSize = serializers.IntegerField(required=False, default=10)


class BatchSelectResponseSerializer(serializers.Serializer):
    results = serializers.DictField(child=SelectResponseSerializer())


class FormSelectsView(APIView):
    @extend_schema(
        parameters=[
            OpenApiParameter("field", str, required=True),
            OpenApiParameter("search", str, required=False),
            OpenApiParameter("page", int, required=False),
            OpenApiParameter("pageSize", int, required=False),
        ],
        responses=SelectResponseSerializer()
    )
    def get(self, request):
        """Legacy endpoint for backward compatibility"""
        field = request.GET.get("field")
        search = request.GET.get("search", "").lower()
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("pageSize", 10))

        if not field:
            return Response({"error": "Field parameter is required"}, status=400)

        # Get options for the single field
        options = self._get_field_options(field)

        # Apply search filter - handle empty search gracefully
        if search:
            options = [opt for opt in options if search in opt["label"].lower()]

        # Apply pagination
        total = len(options)
        start = (page - 1) * page_size
        end = start + page_size
        paginated = options[start:end]

        return Response({
            "data": paginated,
            "currentPage": page,
            "totalPages": max(1, (total + page_size - 1) // page_size)
        })

    @extend_schema(
        request=BatchSelectRequestSerializer,
        responses=BatchSelectResponseSerializer
    )
    def post(self, request):
        """New batch endpoint for fetching multiple fields at once"""
        serializer = BatchSelectRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        fields = serializer.validated_data.get("fields", [])
        search = serializer.validated_data.get("search", "").lower()
        page = serializer.validated_data.get("page", 1)
        page_size = serializer.validated_data.get("pageSize", 10)

        if not fields:
            return Response({"error": "At least one field must be specified"}, status=400)

        results = {}

        for field in fields:
            # Get options for this field
            options = self._get_field_options(field)

            # Apply search filter if provided
            if search:
                options = [opt for opt in options if search in opt["label"].lower()]

            # Apply pagination
            total = len(options)
            start = (page - 1) * page_size
            end = start + page_size
            paginated = options[start:end]

            results[field] = {
                "data": paginated,
                "currentPage": page,
                "totalPages": max(1, (total + page_size - 1) // page_size)
            }

        return Response({"results": results})

    def _get_field_options(self, field):
        """Helper method to get options for a specific field"""
        match field:
            case "application_no":
                return [{"label": f"APP-{i:04}", "value": f"APP-{i:04}"} for i in range(1, 201)]
            case "manager":
                return [{"label": f"Quản lý {i}", "value": f"manager{i}"} for i in range(1, 4)]
            case "customer_code":
                return [{"label": f"Khách hàng {i}", "value": f"customer{i}"} for i in range(1, 4)]
            case "category":
                return [{"label": f"Loại {i}", "value": f"category{i}"} for i in range(1, 4)]
            case "status":
                return [
                    {"label": "Đã duyệt", "value": "approved"},
                    {"label": "Đang chờ", "value": "pending"},
                ]
            case _:
                return []
