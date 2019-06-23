import json
from django.urls import reverse
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from rest_framework.test import APITestCase, APIClient
from rest_framework.views import status
from .models import Books
from .serializers import BooksSerializer

# tests for models


class BooksModelTest(APITestCase):
    def setUp(self):
        self.a_Book = Books.objects.create(
            title="Book A",
            author="Author A",
            available_copies=10
        )

    def test_Book(self):
        """"
        This test ensures that the Book created in the setup
        exists
        """
        self.assertEqual(self.a_Book.title, "Book A")
        self.assertEqual(self.a_Book.author, "Author A")
        self.assertEqual(str(self.a_Book), "Book A")

# tests for views


class BaseViewTest(APITestCase):
    client = APIClient()

    @staticmethod
    def create_book(title="", author="", available_copies=0):
        if title != "" and author != "":
            Books.objects.create(title=title, author=author, available_copies=available_copies)

    def login_a_user(self, username="", password=""):
        url = reverse(
            "auth-login",
        )
        return self.client.post(
            url,
            data=json.dumps({
                "username": username,
                "password": password
            }),
            content_type="application/json"
        )
    @staticmethod
    def create_Book(title="", author="", available_copies=0):
        """
        Create a Book in the db
        :param title:
        :param author:
        ;param available_copies:
        :return:
        """
        if title != "" and author != "":
            Books.objects.create(title=title, author=author, available_copies=available_copies)

    def make_a_request(self, kind="post", **kwargs):
        """
        Make a post request to create a Book
        :param kind: HTTP VERB
        :return:
        """

        if kind == "post":
            return self.client.post(
                reverse(
                    "books-list-create",
                ),
                data=json.dumps(kwargs["data"]),
                content_type='application/json'
            )
        elif kind == "put":
            return self.client.put(
                reverse(
                    "books-detail",
                    kwargs={
                        "pk": kwargs["id"]
                    }
                ),
                data=json.dumps(kwargs["data"]),
                content_type='application/json'
            )
        else:
            return None

    def fetch_a_Book(self, pk=0):
        return self.client.get(
            reverse(
                "books-detail",
                kwargs={
                    "pk": pk
                }
            )
        )

    def delete_a_Book(self, pk=0):
        return self.client.delete(
            reverse(
                "books-detail",
                kwargs={
                    "pk": pk
                }
            )
        )

    def login_client(self, username="", password=""):
        # get a token from DRF
        response = self.client.post(
            reverse("create-token"),
            data=json.dumps(
                {
                    'username': username,
                    'password': password
                }
            ),
            content_type='application/json'
        )
        self.token = response.data['token']
        # set the token in the header
        self.client.credentials(
            HTTP_AUTHORIZATION='Bearer ' + self.token
        )
        self.client.login(username=username, password=password)
        return self.token

    def register_a_user(self, username="", password="", email=""):
        return self.client.post(
            reverse(
                "auth-register",
            ),
            data=json.dumps(
                {
                    "username": username,
                    "password": password,
                    "email": email
                }
            ),
            content_type='application/json'
        )
    def update_password(self, pk, old_password="", new_password=""):
        return self.client.put(
            reverse(
                "modify/delete-user",
                kwargs={
                    "pk": pk
                },
            ),
            data=json.dumps(
                {
                    "old_password": old_password,
                    "new_password": new_password
                }
            ),
            content_type='application/json'
        )

    def delete_user(self, password, pk):
        return self.client.delete(
            reverse(
                "modify/delete-user",
                kwargs={
                    "pk": pk
                },
            ),
            data=json.dumps(
                {
                    "password": password
                },
            ),
            content_type='application/json'
        )

    def issue_book(self, pk):
        return self.client.put(
            reverse(
                "issue-book",
                kwargs={
                    "pk":pk
                },
            ),
            content_type='application/json'
        )
    def return_book(self, pk):
        return self.client.put(
            reverse(
                "return-book",
                kwargs={
                    "pk":pk
                },
            ),
            content_type='application/json'
        )


    def setUp(self):
        # create a admin user
        self.user = User.objects.create_superuser(
            username="test_user",
            email="test@mail.com",
            password="testing",
            first_name="test",
            last_name="user",
        )
        # add test data
        self.create_book("Book1", "A1", 10)
        self.create_book("Book2", "A2", 20)
        self.create_book("Book3", "A3", 30)
        self.create_book("Book4", "A4", 40)

        self.valid_data = {
            "pk" : 5,
            "title": "test Book",
            "author": "test author",
            "available_copies": 10
        }
        self.invalid_data = {
            "title": "",
            "author": "",
            "available_copies":0
        }
        self.valid_Book_id = 1
        self.invalid_Book_id = 100


class GetAllBooksTest(BaseViewTest):

    def test_get_all_books(self):
        """
        This test ensures that all Books added in the setUp method
        exist when we make a GET request to the books/admin endpoint
        """
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.client.get(
            reverse("books-list-create")
        )
        # fetch the data from db
        expected = Books.objects.all()
        serialized = BooksSerializer(expected, many=True)
        self.assertEqual(response.data, serialized.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class GetASingleBooksTest(BaseViewTest):

    def test_get_a_Book(self):
        """
        This test ensures that a single Book of a given id is
        returned
        """
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.fetch_a_Book(self.valid_Book_id)
        # fetch the data from db
        expected = Books.objects.get(pk=self.valid_Book_id)
        serialized = BooksSerializer(expected)
        self.assertEqual(response.data, serialized.data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # test with a Book that does not exist
        response = self.fetch_a_Book(self.invalid_Book_id)
        self.assertEqual(
            response.data["message"],
            "Book with id: 100 does not exist"
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AddBooksTest(BaseViewTest):

    def test_create_a_Book(self):
        """
        This test ensures that a single Book can be added
        """
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.make_a_request(
            kind="post",
            data=self.valid_data
        )
        self.assertEqual(response.data, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # test with invalid data
        response = self.make_a_request(
            kind="post",
            data=self.invalid_data
        )
        self.assertEqual(
            response.data["message"],
            "Both title and author are required to add a book"
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class UpdateBooksTest(BaseViewTest):

    def test_update_a_Book(self):
        """
        This test ensures that a single Book can be updated. In this
        test we update the second Book in the db with valid data
        """
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.make_a_request(
            kind="put",
            id=2,
            data=self.valid_data
        )
        self.assertEqual(response.data, self.valid_data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)


class DeleteBooksTest(BaseViewTest):

    def test_delete_a_Book(self):
        """
        This test ensures that when a Book of given id can be deleted
        """
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.delete_a_Book(1)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # test with invalid data
        response = self.delete_a_Book(100)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AuthLoginUserTest(BaseViewTest):
    """
    Tests for the auth/login/ endpoint
    """

    def test_login_user_with_valid_credentials(self):
        # test login with valid credentials
        response = self.login_a_user("test_user", "testing")
        # assert token key exists
        self.assertIn("token", response.data)
        # assert status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # test login with invalid credentials
        response = self.login_a_user("anonymous", "pass")
        # assert status code is 401 UNAUTHORIZED
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class AuthRegisterUserTest(BaseViewTest):
    """
    Tests for auth/register/ endpoint
    """
    def test_register_a_user(self):
        response = self.register_a_user("new_user", "new_pass", "new_user@mail.com")
        # assert status code is 201 CREATED
        self.assertEqual(response.data["username"], "new_user")
        self.assertEqual(response.data["email"], "new_user@mail.com")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # test with invalid data
        response = self.register_a_user()
        # assert status code
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

class AuthModifyUserTest(BaseViewTest):
    """
        Tests for auth/user/id endpoint
        """
    def test_update_password(self):
        self.register_a_user("new_user", "new_pass", "new_user@mail.com")
        user = get_object_or_404(User, username='new_user')
        pk = user.pk
        response = self.update_password(pk, "new_pass", "newer_pass")
        # assert token key exists
        self.assertIn("token", response.data)
        # assert status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_delete_user(self):
        self.register_a_user("new_user", "new_pass", "new_user@mail.com")
        user = get_object_or_404(User, username='new_user')
        pk = user.pk

        # delete user with wrong passord
        response = self.delete_user("wrong_pass", pk)
        self.assertEqual(response.data["message"], "Incorrect Password")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        # delete user by providing correct password
        response= self.delete_user("new_pass", pk)
        # assert user is deleted by blank response
        self.assertEqual(response.status_code,status.HTTP_204_NO_CONTENT)


class ManageBookIssueTest(BaseViewTest):

    def test_book_issue_and_return(self):
        self.login_client('test_user', 'testing')
        # hit the API endpoint
        response = self.issue_book(1)
        self.assertEqual(response.data["message"], "Book Book1 Issued")
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

        # issue with invalid pk
        response=self.issue_book(100)
        self.assertEqual(response.data["message"], "Book with id: 100 does not exist in the database")
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

        # return the book
        response = self.return_book(1)
        self.assertEqual(response.data["message"], "Book Book1 Returned")
        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)

        # returning incorrect book
        response = self.return_book(2)
        self.assertEqual(response.data["message"], "You never issued the book: Book2")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

