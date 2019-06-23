from django.urls import path
from .views import ListCreateBooksView, BooksDetailView, LoginView,\
    RegisterUsers, UserView, BookIssueView, AllBooksView, ReturnBookView


urlpatterns = [
    # CRUD for Books model (only admin can access)
    path('books/admin/', ListCreateBooksView.as_view(), name="books-list-create"),
    path('books/<int:pk>/admin/', BooksDetailView.as_view(), name="books-detail"),

    # Endpoint for an authenticated user to view all the books
    path('books/', AllBooksView.as_view(), name="all-books-view"),

    # Endpoint to issue a book
    path('books/<int:pk>/', BookIssueView.as_view(), name="issue-book"),

    # Endpoint to return a book
    path('books/<int:pk>/return/', ReturnBookView.as_view(), name="return-book"),

    # CRUD for User model
    path('auth/login/', LoginView.as_view(), name="auth-login"),
    path('auth/register/', RegisterUsers.as_view(), name="auth-register"),
    path('auth/user/<int:pk>/', UserView.as_view(), name="modify/delete-user"),
]