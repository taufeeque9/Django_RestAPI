from rest_framework.response import Response
from rest_framework.views import status


def validate_request_data(fn):
    def decorated(*args, **kwargs):
        # args[0] == GenericView Object
        title = args[0].request.data.get("title", "")
        author = args[0].request.data.get("author", "")

        if not title or not author:
            return Response(
                data={
                    "message": "Both title and author are required to add a book"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        return fn(*args, **kwargs)
    return decorated