from django.test import TestCase
from django.contrib.auth import get_user_model
from django.db import IntegrityError
from rest_framework.test import APIClient,APITestCase
from rest_framework import status
from rest_framework.authtoken.models import Token
from django.urls import reverse
from django.contrib.auth.hashers import make_password

User = get_user_model()

def create_user(username='user',
                    email='test@example.com',
                    password='pass13'):
        """Function to create normal user"""
        user = User.objects.create_user(username=username,
                                        email=email,
                                        password=password)
        return user

def create_super_user(username='user',
                    email='test@example.com',
                    password='pass13'):
        """Function to create super user"""
        user = User.objects.create_superuser(username=username,
                                        email=email,
                                        password=password)
        return user


class UsersTest(APITestCase):

    def setUp(self):
        """Setup which will run before every tests"""
        self.client = APIClient() 
    
    def user_login(self,username=None,password=None):
            """Authenticates the user"""
            client = APIClient()
            res = client.login(username=username, 
                             password=password,)
            return res

    def test_to_check_valid_credentials(self):
        print("\nRunning test_to_check_valid_credentials...", end="", flush=True)
        user1 = create_user(username='user1', 
                                  email='user1@example.com',
                                )
        Login = self.user_login(username=user1.email,
                                password='pass1')
        self.assertFalse(Login)
        print(" ✅ Passed!")

    def test_to_generate_token_for_authenticated_superuser(self):
        print("\nRunning test_to_generate_token_for_authenticated_superuser...", end="", flush=True)
        user1 = create_super_user(username='user1', 
                                  email='user1@example.com',
                                )
        Login = self.user_login(username=user1.email,
                                password='pass13')

        self.assertTrue(Login)
        token = Token.objects.create(user=user1)
        self.assertTrue(isinstance(token.key,str))
        self.assertGreater(len(token.key),0)
        user_token = Token.objects.get(user=user1)
        self.assertEqual(token,user_token)
        print(" ✅ Passed!")

    def test_to_create_superuser_by_superuser(self):
        '''test to create superuser'''
        print("\nRunning test_to_create_superuser_by_superuser...", end="", flush=True)
        user1 = create_super_user(username='user1', 
                                  email='user1@example.com',
                                )
        Login = self.user_login(username=user1.email,
                                password='pass13')

        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertTrue(user1.is_superuser)
        payload = {'username' : 'test user',
                   'email' : 'testuser@example.com',
                   'password' : 'pass123',
                   'is_superuser': True}
        res = self.client.post(reverse('user-list'), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        get_user = User.objects.get(username=payload['username'])
        self.assertTrue(get_user.is_superuser)
        self.assertEqual(get_user.username, payload['username'])
        print(" ✅ Passed!")

    def test_to_create_normal_user_by_superuser(self):
        """Test to create a normal user by admin """
        print("\nRunning test_to_create_normal_user_by_superuser...", end="", flush=True)
        user1 = create_super_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertTrue(user1.is_superuser)
        payload = {'username' : 'test user',
                   'email' : 'testuser@example.com',
                   'password' : 'pass123',}
        res = self.client.post(reverse('user-list'), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        get_user = User.objects.get(username=payload['username'])
        self.assertEqual(get_user.username, payload['username'])
        self.assertFalse(get_user.is_superuser)
        print(" ✅ Passed!")

    def test_to_delete_superuser_by_superuser(self):
        """Test to delete a superuser account"""
        print("\nRunning test_to_delete_superuser_by_superuser...", end="", flush=True)
        user1 = create_super_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertTrue(user1.is_superuser)
        payload = {'username' : 'test user',
                   'email' : 'testuser@example.com',
                   'password' : 'pass123',
                   'is_superuser': True}
        res = self.client.post(reverse('user-list'), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        get_user = User.objects.get(username=payload['username'])
        res = self.client.delete(reverse('user-detail',args=[get_user.id]))
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        get_user = User.objects.filter(username=payload['username'])
        self.assertEqual(len(get_user),0)
        print(" ✅ Passed!")

    def test_to_update_users_by_superuser(self):
        """test to update users"""
        print("\nRunning test_to_update_user_by_superuser...", end="", flush=True)
        user1 = create_super_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertTrue(user1.is_superuser)
        payload = {'username' : 'test user',
                   'email' : 'testuser@example.com',
                   'password' : 'pass123',
                   'is_superuser': True}
        res = self.client.post(reverse('user-list'), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        data = {'email' : 'testuser1@example.com',
                'username' : 'test user',
                }
        user_id = User.objects.filter(username = payload['username'])[0].id
        res = self.client.put(reverse('user-detail',args=[user_id]),data, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        user_mail = User.objects.filter(username = payload['username'])[0].email
        self.assertEqual(user_mail, data['email'])
        print(" ✅ Passed!")

    def test_to_do_partial_update_users_by_superuser(self):
        """Test to do parial update i.e particular field"""
        print("\nRunning test_to_do_partial_update_to_users_by_superuser...", end="", flush=True)
        user1 = create_super_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertTrue(user1.is_superuser)
        payload = {'username' : 'test user',
                   'email' : 'testuser@example.com',
                   'password' : 'pass123',
                   'is_superuser': True}
        res = self.client.post(reverse('user-list'), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        data = {'email' : 'testuser1@example.com',
                }
        user_id = User.objects.filter(username = payload['username'])[0].id
        res = self.client.patch(reverse('user-detail',args=[user_id]), 
                            data, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        user_mail = User.objects.filter(username = payload['username'])[0].email
        self.assertEqual(user_mail, data['email'])
        self.assertNotEqual(user_mail, payload['email'])
        print(" ✅ Passed!")

    def test_to_retrive_data_by_normal_user(self):
        """Test to retrive data for normal users"""
        print("\nRunning test_to_retrive_data_by_normal_users...", end="", flush=True)
        user1 = create_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        user2 = create_super_user("admin", 
                                "admin@example.com",
                                "pass13",)
        user3 = create_user('user3', 'user3@example.com', 
                            'pass13')
        res = self.client.get(reverse('user-list'))
        self.assertEqual(res.status_code,status.HTTP_200_OK)
        self.assertEqual(len(res.data), 1)
        print(" ✅ Passed!")

    def test_to_retrive_data_by_super_user(self):
        """Test to retrive data for normal users"""
        print("\nRunning test_to_retrive_data_by_superuser...", end="", flush=True)
        user1 = create_super_user("admin", 
                                "admin@example.com",
                                "pass13",)
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertTrue(user1.is_superuser)
        user2 = create_user()
        user3 = create_user('user3', 'user3@example.com', 
                            'pass13')
        res = self.client.get(reverse('user-list'))
        self.assertEqual(res.status_code,status.HTTP_200_OK)
        self.assertEqual(len(res.data), 3)
        print(" ✅ Passed!")

    def test_to_update_user_by_normal_user(self):
        """Test to update a user acc by normal user"""
        print("\nRunning test_to_update_user_by_normal_user...", end="", flush=True)
        user1 = create_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        url = self.client.get(reverse('user-detail',args=[user1.id]))
        payload = {'username':'vignesh',
                   'email':'test@example.com'}
        res = self.client.put(reverse('user-detail', args=[user1.id]), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        user1.refresh_from_db()
        self.assertEqual(payload['username'], user1.username)
        print(" ✅ Passed!")
    
    def test_to_update_another_user_by_normal_user(self):
        """Test to update a another user acc by normal user"""
        print("\nRunning test_to_update_another_user_by_normal_user...", end="", flush=True)
        user1 = create_user()
        user2 = create_user('user3', 'user3@example.com', 
                            'pass13')
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        url = self.client.get(reverse('user-detail',args=[user1.id]))
        payload = {'username':'vignesh',
                   'email':'user3@example.com'}
        res = self.client.put(reverse('user-detail', args=[user2.id]), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)
        self.assertEqual('user3', user2.username)
        print(" ✅ Passed!")

    def test_to_do_partial_update_a_user_by_normal_user(self):
        """Test to partial update a user acc by normal user"""
        print("\nRunning test_to_do_a_partial_update_to_user_by_normal_user...", end="", flush=True)
        user1 = create_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        payload = {'username':'vignesh',}
        res = self.client.patch(reverse('user-detail', args=[user1.id]), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        user1.refresh_from_db()
        self.assertEqual(payload['username'], user1.username)
        print(" ✅ Passed!")

    def test_to_do_partial_update_to_another_user_by_normal_user(self):
        """Test to partial update another user acc by normal user"""
        print("\nRunning test_to_do_a_partial_update_to_another_user_by_normal_user...", end="", flush=True)
        user1 = create_user()
        user2 = create_user('user3', 'user3@example.com', 
                            'pass13')
        user2.refresh_from_db()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        payload = {'username':'vignesh',}
        res = self.client.patch(reverse('user-detail', args=[user2.id]), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)
        user1.refresh_from_db()
        self.assertEqual('user3', user2.username)
        print(" ✅ Passed!")

    def test_to_create_a_user_by_normal_user(self):
        """Test to create a user by normal user"""
        print("\nRunning test_to_create_a_user_by_normal_user...", end="", flush=True)
        user1 = create_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        payload = {'username':'user3', 
                   'email':'user3@example.com', 
                    'password':'pass13',}
        res = self.client.post(reverse('user-list'), payload, format='json')
        self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        user1.refresh_from_db()
        exists = User.objects.filter(username=payload['username']).exists()
        self.assertFalse(exists)
        print(" ✅ Passed!")

    def test_to_delete_user_by_normal_user(self):
        """Test to delete own user acc"""
        print("\nRunning test_to_delete_own_acc_by_normal_user...", end="", flush=True)
        user1 = create_user()
        Login = self.user_login(username=user1.email, 
                                password='pass13')
        self.assertTrue(Login)
        token, _ = Token.objects.get_or_create(user=user1)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')
        self.assertFalse(user1.is_superuser)
        res = self.client.delete(reverse('user-detail', args=[user1.id]),format='json')
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        Token.objects.filter(user=user1).delete()
        exists = User.objects.filter(username=user1.username).exists()
        self.assertFalse(exists)
        token = Token.objects.filter(user=user1).exists()
        self.assertFalse(token)
        print(" ✅ Passed!")

    ### tmrw write test to delete acc by normal user for both own acc and other acc