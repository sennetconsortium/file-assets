import json

is_local_logging = False


def enable_local_logging():
    global is_local_logging
    is_local_logging = True


def lambda_handler(event, context):
    print('Starting file-assets authorization ...')
    print('Logging event ...')
    if is_local_logging:
        print(json.dumps(event, indent=4))
    else:
        # This enables a multiline string in one row of the Cloudwatch logs
        # Otherwise each line of the JSON will be printed on a separate line in the logs
        # This is only needed when running on AWS
        print(json.dumps(event, indent=4).replace('\n', '\r'))

    bearer_token = event['headers']['Authorization']
    print('Logging token ...')
    # Remove the `Bearer ` part of the token
    token = bearer_token[7:]
    print(token)
    effect = 'Allow'

    path = event['path'].strip('/')
    asset_id, file_name = path.split('/')
    print('Asset ID: ' + asset_id)
    print('File name: ' + file_name)

    principal_id = "default_user|a1b2c3d4"
    method_arn = event['methodArn']
    policy = AuthPolicy(principal_id, effect, method_arn)
    auth_response = policy.build()
    print('END file-assets authorization')
    return auth_response


# https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-lambda-authorizer-output.html
# A Lambda authorizer function's output is a dictionary-like object, which must include
# the principal identifier (principalId) and a policy document (policyDocument) containing a list of policy statements.
class AuthPolicy(object):
    # The principal used for the policy, this should be a unique identifier for the end user
    principal_id = ""

    # The policy version used for the evaluation. This should always be '2012-10-17'
    version = "2012-10-17"

    effect = ""

    method_arn = ""

    def __init__(self, principal_id, effect, method_arn):
        self.principal_id = principal_id
        self.effect = effect
        self.method_arn = method_arn

    def build(self):
        policy = {
            'principalId': self.principal_id,
            'policyDocument': {
                'Version': self.version,
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': self.effect,
                        'Resource': self.method_arn
                    }
                ]
            }
        }

        return policy
