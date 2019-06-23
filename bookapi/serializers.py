from rest_framework import serializers
from .models import Books
from django.contrib.auth.models import User

class BooksSerializer(serializers.ModelSerializer):
    class Meta:
        model = Books
        fields = ("pk", "title", "author", "available_copies")

        def update(self, instance, validated_data):
            instance.title = validated_data.get("title", instance.title)
            instance.artist = validated_data.get("author", instance.author)
            instance.available_copies = validated_data.get("available_copies", instance.available_copies)
            instance.save()
            return instance

class BooksSerializer2(serializers.ModelSerializer):
    status = serializers.SerializerMethodField()
    class Meta:
        model = Books
        fields = ("pk", "title", "author", "available_copies", "status")

    def get_status(self, obj):
        req = self.context.get("request")
        if req is not None:
            user = req.user
            if user in obj.users_lended.all():
                return "Already Rented"
        if obj.available_copies > 0 :
            return "Available"
        else: return "Not Available"

        
class TokenSerializer(serializers.Serializer):
    """
    This serializer serializes the token data
    """
    token = serializers.CharField(max_length=255)

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ("username", "email")
