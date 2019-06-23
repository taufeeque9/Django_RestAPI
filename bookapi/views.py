from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login

from rest_framework import generics
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework.views import status
from rest_framework_jwt.settings import api_settings

from .decorators import validate_request_data
from .models import Books
from .serializers import BooksSerializer, TokenSerializer, UserSerializer, BooksSerializer2

# Get the JWT settings
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER


class ListCreateBooksView(generics.ListCreateAPIView):
    """
    GET books/admin/
    POST books/admin/
    """
    queryset = Books.objects.all()
    serializer_class = BooksSerializer
    permission_classes = (permissions.IsAdminUser,)

    @validate_request_data
    def post(self, request, *args, **kwargs):
        a_book = Books.objects.create(
            title=request.data["title"],
            author=request.data["author"],
            available_copies=request.data["available_copies"]
        )
        return Response(
            data=BooksSerializer(a_book).data,
            status=status.HTTP_201_CREATED
        )


class BooksDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET books/:id/admin/
    PUT books/:id/admin/
    DELETE books/:id/admin/
    """
    queryset = Books.objects.all()
    permission_classes = (permissions.IsAdminUser,)

    def get(self, request, *args, **kwargs):
        try:
            a_book = self.queryset.get(pk=kwargs["pk"])
            return Response(BooksSerializer(a_book).data)
        except Books.DoesNotExist:
            return Response(
                data={
                    "message": "Book with id: {} does not exist".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )

    def put(self, request, *args, **kwargs):
        try:
            a_book = self.queryset.get(pk=kwargs["pk"])
            serializer = BooksSerializer()
            updated_book = serializer.update(a_book, request.data)
            return Response(BooksSerializer(updated_book).data)
        except Books.DoesNotExist:
            return Response(
                data={
                    "message": "Book with id: {} does not exist".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, *args, **kwargs):
        try:
            a_book = self.queryset.get(pk=kwargs["pk"])
            a_book.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Books.DoesNotExist:
            return Response(
                data={
                    "message": "Book with id: {} does not exist".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )


class LoginView(generics.CreateAPIView):
    """
    POST auth/login/
    """

    # This permission class will over ride the global permission
    # class setting
    permission_classes = (permissions.AllowAny,)
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        username = request.data.get("username", "")
        password = request.data.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            # login saves the user’s ID in the session,
            # using Django’s session framework.
            login(request, user)
            serializer = TokenSerializer(data={
                # using drf jwt utility functions to generate a token
                "token": jwt_encode_handler(
                    jwt_payload_handler(user)
                )})
            serializer.is_valid()
            return Response(serializer.data)
        return Response(status=status.HTTP_401_UNAUTHORIZED)


class RegisterUsers(generics.CreateAPIView):
    """
    POST auth/register/
    """
    permission_classes = (permissions.AllowAny,)

    def post(self, request, *args, **kwargs):
        username = request.data.get("username", "")
        password = request.data.get("password", "")
        email = request.data.get("email", "")
        if not username and not password and not email:
            return Response(
                data={
                    "message": "username, password and email is required to register a user"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        new_user = User.objects.create_user(
            username=username, password=password, email=email
        )
        return Response(
            data=UserSerializer(new_user).data,
            status=status.HTTP_201_CREATED
        )

class UserView(generics.RetrieveUpdateDestroyAPIView):
    queryset = User.objects.all()
    def put(self, request, *args, **kwargs):
        try:
            user = self.queryset.get(pk=kwargs["pk"])
            old_password = request.data.get("old_password")
            new_password = request.data.get("new_password")
            # if user is None:
            #     return Response(status=status.HTTP_401_UNAUTHORIZED)
            if not old_password:
                return Response(
                    data={
                        "message": "Please enter old_password".format(kwargs["pk"])
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            if not new_password:
                return Response(
                    data={
                        "message": "Please enter new_password".format(kwargs["pk"])
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                # login saves the user’s ID in the session,
                # using Django’s session framework.
                login(request, user)
                serializer = TokenSerializer(data={
                    # using drf jwt utility functions to generate a token
                    "token": jwt_encode_handler(
                        jwt_payload_handler(user)
                    )})
                serializer.is_valid()
                return Response(serializer.data)
            if not user.check_password(old_password):
                return Response(
                    data={
                        "message": "Incorrect Password".format(kwargs["pk"])
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

        except User.DoesNotExist:
            return Response(
                data={
                    "message": "User with id: {} does not exist".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )

    def delete(self, request, *args, **kwargs):
        try:
            user = self.queryset.get(pk=kwargs["pk"])
            password = request.data.get("password")
            if user.check_password(password):
                user.delete()
                return Response(status=status.HTTP_204_NO_CONTENT)
            else:
                return Response(
                    data={
                        "message": "Incorrect Password".format(kwargs["pk"])
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
        except User.DoesNotExist:
            return Response(
                data={
                    "message": "User with id: {} does not exist".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )

class AllBooksView(generics.ListAPIView):
    queryset = Books.objects.all()
    serializer_class = BooksSerializer2
    permission_classes = (permissions.IsAuthenticatedOrReadOnly,)


class BookIssueView(generics.UpdateAPIView):
    queryset = Books.objects.all()
    permission_classes = (permissions.IsAuthenticated,)

    def put(self, request, *args, **kwargs):
        try:
            book = self.queryset.get(pk=kwargs["pk"])
            available_copies = book.available_copies - 1
            if request.user in book.users_lended.all():
                return Response(
                    data={
                        "message": "You already have the book: {}".format(book.title)
                    },
                    status=status.HTTP_400_BAD_REQUEST)
            if available_copies < 0:
                return Response(
                    data={
                        "message": "{} is currently not available".format(book.title)
                    },
                    status=status.HTTP_400_BAD_REQUEST)

            book.available_copies = available_copies
            user = request.user
            book.users_lended.add(user)
            book.save()

            return Response(
                data={
                    "message": "Book {} Issued".format(book.title)
                },
                status=status.HTTP_202_ACCEPTED)
        except Books.DoesNotExist:
            return Response(
                data={
                    "message": "Book with id: {} does not exist in the database".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )

class ReturnBookView(generics.UpdateAPIView):
    queryset = Books.objects.all()
    permission_classes = (permissions.IsAuthenticated,)
    def put(self, request, *args, **kwargs):
        user = request.user
        pk = kwargs["pk"]
        book = Books.objects.get(pk=pk)
        try:
            if user in book.users_lended.all():
                book.users_lended.remove(user)
                book.available_copies += 1
                book.save()
                return Response(
                data = {
                           "message": "Book {} Returned".format(book.title)
                       },
                status = status.HTTP_202_ACCEPTED)
            else :
                return Response(
                    data={
                        "message": "You never issued the book: {}".format(book.title)
                    },
                    status=status.HTTP_400_BAD_REQUEST)
        except Books.DoesNotExist:
            return Response(
                data={
                    "message": "Book with id: {} does not exist in the database".format(kwargs["pk"])
                },
                status=status.HTTP_404_NOT_FOUND
            )



