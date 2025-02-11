from rest_framework import serializers
from .models import User
from django.contrib.auth.hashers import make_password


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)
    class Meta:
        model = User
        fields = ['username','email','first_name','last_name','is_superuser','password']
        extra_kwargs = {'is_superuser' :{
                            'read_only':True,
                        }
                        }

    def validate(self, attrs):
        if self.instance is None and 'password' not in attrs:
            raise serializers.ValidationError({"password" : "This Field is required."})
        return attrs

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])
        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])
        return super().update(instance, validated_data)