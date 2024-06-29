import json
from django.test import TestCase, RequestFactory
from login.models import User
from login.endpoints.register_login import register_endpoint

# Create your tests here.

class register_Test(TestCase):
    def setUp(self):
        pass

    def test_empty_json(self):
        json_data = {}
        response = self.client.post('/register/',
                                    json.dumps(json_data),
                                    content_type="application/json")
        self.assertIn(response.status_code, [400, 401])

    def test_int_in_field(self):
        json_data = {
            "login": 4,
            "password": 5,
            "display_name": 5
        }
        response = self.client.post('/register/',
                                    json.dumps(json_data),
                                    content_type="application/json")
        self.assertIn(response.status_code, [400, 401])
