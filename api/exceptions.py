from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status


def custom_exception_handler(exc, context):
    """
    Custom exception handler for unified API error responses.
    """
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)

    # If response is None, there was an unhandled exception
    if response is None:
        return Response(
            {
                "error": True,
                "message": str(exc),
                "details": "An unexpected error occurred."
            },
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    # Format the response based on status code
    if response.status_code == 400:
        error_message = "Invalid input data."
    elif response.status_code == 401:
        error_message = "Authentication credentials were not provided or are invalid."
    elif response.status_code == 403:
        error_message = "You do not have permission to perform this action."
    elif response.status_code == 404:
        error_message = "The requested resource was not found."
    elif response.status_code == 405:
        error_message = "Method not allowed."
    elif response.status_code == 429:
        error_message = "Request limit exceeded. Please try again later."
    else:
        error_message = "An error occurred."

    # Create a custom response format
    custom_response_data = {
        "error": True,
        "message": error_message,
        "details": response.data
    }

    response.data = custom_response_data
    return response
