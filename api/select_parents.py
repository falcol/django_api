from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Dữ liệu mẫu
PROVINCES = [
    {"label": "Hà Nội", "value": "HN"},
    {"label": "Hồ Chí Minh", "value": "HCM"},
]

DISTRICTS = {
    "HN": [
        {"label": "Ba Đình", "value": "badinh"},
        {"label": "Đống Đa", "value": "dongda"},
    ],
    "HCM": [
        {"label": "Quận 1", "value": "q1"},
        {"label": "Quận 3", "value": "q3"},
    ],
}

class SelectParentChildView(APIView):
    def get(self, request):
        level = request.GET.get("level")
        parent = request.GET.get("parent")

        if level == "province":
            return Response(PROVINCES)
        elif level == "district" and parent:
            return Response(DISTRICTS.get(parent, []))
        else:
            return Response([], status=status.HTTP_400_BAD_REQUEST)
