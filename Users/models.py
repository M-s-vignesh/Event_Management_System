from django.db import models
from django.contrib.auth.models \
    import (BaseUserManager,
            AbstractBaseUser,
            AbstractUser,
            PermissionsMixin,
            )
from django.template.defaultfilters import slugify

# Create your models here.

class UserManager(BaseUserManager):
    use_in_migrations = True
    def _create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('The given email must be set')
        if not username:
            raise ValueError("Username must be set")
        email = self.normalize_email(email)
        user = self.model(username=username, 
                        email=email, 
                        **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email,username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, username, password, **extra_fields)
        

    def create_superuser(self, email, username, password=None, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, username ,password, **extra_fields)

class User(AbstractBaseUser,PermissionsMixin):
    username = models.CharField(max_length=35, blank=False, unique=True)
    email = models.EmailField( unique=True)
    first_name = models.CharField( max_length=30, blank=True)
    last_name = models.CharField( max_length=30, blank=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    slug = models.SlugField(unique=True,null=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']
    objects = UserManager()

    def __str__(self):
        return self.username
    
    def get_full_name(self):
        '''
        Returns the first_name plus the last_name, with a space in between.
        '''
        full_name = '%s %s' % (self.first_name, self.last_name)
        return full_name.strip()

    def get_short_name(self):
        '''
        Returns the short name for the user.
        '''
        return self.first_name

    def save(self, *args, **kwargs):  # new
        if not self.slug:
            self.slug = slugify(self.username)
        return super().save(*args, **kwargs)

