import json
import unittest
from auth.lambda_function import lambda_handler, enable_local_logging

# A request for a consortium dataset with a token that has consortium access
with open('request_for_consortium_dataset_with_consortium_level_token.json') as f:
    consortium_dataset_with_consortium_token = json.load(f)

# A request for a consortium dataset but no token is present
with open('request_for_consortium_dataset_with_no_token.json') as f:
    consortium_dataset_with_no_token = json.load(f)

# A request for a protected dataset with a token that has consortium access
with open('request_for_protected_dataset_with_consortium_level_token.json') as f:
    protected_dataset_with_consortium_token = json.load(f)

enable_local_logging()


class TheUserHasPublicAccessLevel(unittest.TestCase):

    def test_the_token_has_consortium_access_with_a_request_for_a_consortium_file_expecting_status_code_200(self):
        result = lambda_handler(consortium_dataset_with_consortium_token, None)
        self.assertEqual(200, result['statusCode'])

    def test_a_token_is_not_present_with_a_request_for_a_consortium_file_expecting_status_code_401(self):
        result = lambda_handler(consortium_dataset_with_no_token, None)
        self.assertEqual(401, result['statusCode'])

    def test_a_request_for_protected_file_expecting_status_code_403(self):
        result = lambda_handler(protected_dataset_with_consortium_token, None)
        self.assertEqual(403, result['statusCode'])


if __name__ == '__main__':
    unittest.main()
