from rest_framework.views import exception_handler
from rest_framework.response import Response
from rest_framework import status

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    # Now you add your own processing here if response is None
    if response is None:
        response = Response({'detail': 'A server error occurred.'},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    return response