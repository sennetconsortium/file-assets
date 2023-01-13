import json
import unittest
from auth.lambda_function import lambda_handler, enable_local_logging

with open('lambda_event.json') as f:
    event = json.load(f)

enable_local_logging()


def extract_auth_policy_effect(auth_policy):
    effect = auth_policy['policyDocument']['Statement'][0]['Effect']
    return effect


# Given the user passes a valid groups token
# Given they have `public` access level in the group which the dataset belongs to
class TheUserHasPublicAccessLevel(unittest.TestCase):
    # When they request a file from a `public` dataset
    # Then the auth policy effect will be `allow`
    def test_user_has_public_access_and_requests_a_public_file_expecting_auth_policy_effect_is_allow(self):
        auth_policy = lambda_handler(event, None)
        effect = extract_auth_policy_effect(auth_policy)
        self.assertEqual('Allow', effect)

    # When they request a file from a `consortium` dataset
    # Then the auth policy effect will be `deny`
    def test_user_has_public_access_and_requests_a_consortium_file_expecting_auth_policy_effect_is_deny(self):
        self.assertEqual(True, False)

    # When they request a file from a `protected` dataset
    # Then the auth policy effect will be `deny`
    def test_user_has_public_access_and_requests_a_protected_file_expecting_auth_policy_effect_is_deny(self):
        self.assertEqual(True, False)


# Given the user passes a valid groups token
# Given they have `consortium` access level in the group which the dataset belongs to
class TheUserHasConsortiumAccessLevel(unittest.TestCase):
    # When they request a file from a `public` dataset
    # Then the auth policy effect will be `allow`
    def test_user_has_consortium_access_and_requests_a_public_file_expecting_auth_policy_effect_is_allow(self):
        self.assertEqual(True, False)

    # When they request a file from a `consortium` dataset
    # Then the auth policy effect will be `allow`
    def test_user_has_consortium_access_and_requests_a_consortium_file_expecting_auth_policy_effect_is_allow(self):
        self.assertEqual(True, False)

    # When they request a file from a `protected` dataset
    # Then the auth policy effect will be `deny`
    def test_user_has_consortium_access_and_requests_a_protected_file_expecting_auth_policy_effect_is_deny(self):
        self.assertEqual(True, False)


# Given the user passes a valid groups token
# Given they have a `protected` access level in the group which the dataset belongs to
class TheUserHasProtectedAccessLevel(unittest.TestCase):
    # When they request a file from a `public` dataset
    # Then the auth policy effect will be `allow`
    def test_user_has_protected_access_and_requests_a_public_file_expecting_auth_policy_effect_is_allow(self):
        self.assertEqual(True, False)

    # When they request a file from a `consortium` dataset
    # Then the auth policy effect will be `allow`
    def test_user_has_protected_access_and_requests_a_consortium_file_expecting_auth_policy_effect_is_allow(self):
        self.assertEqual(True, False)

    # When they request a file from a `protected` dataset
    # Then the auth policy effect will be `allow`
    def test_user_has_protected_access_and_requests_a_protected_file_expecting_auth_policy_effect_is_allow(self):
        self.assertEqual(True, False)


if __name__ == '__main__':
    unittest.main()
