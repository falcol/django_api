from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

# Tạo nhiều tỉnh/thành phố để test phân trang
PROVINCES = [
    {"label": f"Tỉnh {i}", "value": f"province_{i}"} for i in range(1, 51)
]

DISTRICTS = {
    f"province_{i}": [
        {"label": f"Quận {j} của Tỉnh {i}", "value": f"district_{i}_{j}"}
        for j in range(1, 21)
    ]
    for i in range(1, 51)
}

WARDS = {
    f"district_{i}_{j}": [
        {"label": f"Phường {k} của Quận {j} Tỉnh {i}", "value": f"ward_{i}_{j}_{k}"}
        for k in range(1, 11)
    ]
    for i in range(1, 51) for j in range(1, 21)
}

class SelectParentChildView(APIView):
    def get(self, request):
        level = request.GET.get("level")
        parent = request.GET.get("parent")
        page = int(request.GET.get("page", 1))
        page_size = int(request.GET.get("pageSize", 10))
        search = request.GET.get("search", "").lower()

        if level == "province":
            options = PROVINCES
        elif level == "district" and parent:
            options = DISTRICTS.get(parent, [])
        elif level == "ward" and parent:
            options = WARDS.get(parent, [])
        else:
            return Response([], status=status.HTTP_400_BAD_REQUEST)

        # Lọc theo search dựa trên value thay vì label
        if search:
            options = [opt for opt in options if search in opt["value"].lower()]

        total = len(options)
        start = (page - 1) * page_size
        end = start + page_size
        paginated = options[start:end]

        return Response({
            "data": paginated,
            "currentPage": page,
            "totalPages": (total + page_size - 1) // page_size,
            "total": total,
        })
