import json
import requests
import time
import os
from hubmap_commons.hm_auth import AuthHelper
from hubmap_commons.exceptions import HTTPException
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables
GLOBUS_APP_CLIENT_ID = os.environ['GLOBUS_APP_CLIENT_ID']
GLOBUS_APP_CLIENT_SECRET = os.environ['GLOBUS_APP_CLIENT_SECRET']
ENTITY_API_URL = os.environ['ENTITY_API_URL']
UUID_API_URL = os.environ['UUID_API_URL']

# Initialize AuthHelper class and ensure singleton
try:
    if AuthHelper.isInitialized() == False:
        auth_helper_instance = AuthHelper.create(GLOBUS_APP_CLIENT_ID, GLOBUS_APP_CLIENT_SECRET)

        print("Initialized AuthHelper class successfully :)")
    else:
        auth_helper_instance = AuthHelper.instance()
except Exception:
    msg = "Failed to initialize the AuthHelper class"
    # Log the full stack trace, prepend a line with our message
    print(msg)

is_local_logging = False


# Format the lambda event object for localhost logging
# Only called from the unit tests
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

    bearer_token = event['headers']['authorization']
    # Remove the `Bearer ` part of the token
    token = bearer_token[7:]

    path = event['headers']['x-original-uri'].strip('/')
    asset_id, file_name = path.split('/')
    print('Asset ID: ' + asset_id)
    print('File name: ' + file_name)

    access = get_file_access(asset_id, token, None)
    if access == 200:
        result = 'Allow'
    else:
        result = 'Deny'

    print('RESULT: ' + result)
    return result


def make_api_request_get(target_url):
    now = time.ctime(int(time.time()))

    print(f'Making an HTTP request to GET {target_url} at time {now}')

    # Use modified version of globus app secret from configuration as the internal token
    request_headers = create_request_headers_for_auth(auth_helper_instance.getProcessSecret())

    # Disable ssl certificate verification
    response = requests.get(url=target_url, headers=request_headers, verify=False)

    return response


# Create a dict with HTTP Authorization header with Bearer token
def create_request_headers_for_auth(token):
    auth_header_name = 'Authorization'
    auth_scheme = 'Bearer'

    headers_dict = {
        # Don't forget the space between scheme and the token value
        auth_header_name: auth_scheme + ' ' + token
    }

    return headers_dict


# Due to Flask's EnvironHeaders is immutable
# We create a new class with the headers property 
# so AuthHelper can access it using the dot notation req.headers
class CustomRequest:
    # Constructor
    def __init__(self, headers):
        self.headers = headers


# Check if the target file associated with this uuid is accessible 
# based on token and access level assigned to the entity
# The uuid passed in could either be a real entity (Donor/Sample/Dataset) uuid or
# a file uuid (Dataset: thumbnail image or Donor/Sample: metadata/image file)
# AVR file uuid is handled via uuid-api only and no token is required
def get_file_access(uuid, token_from_query, request):
    # AVR and AVR files are standalone, not stored in neo4j and won't be available via entity-api
    supported_entity_types = ['Source', 'Sample', 'Dataset']

    # Returns one of the following codes
    allowed = 200
    bad_request = 400
    authentication_required = 401
    authorization_required = 403
    not_found = 404
    internal_error = 500

    # All lowercase for easy comparison
    ACCESS_LEVEL_PUBLIC = 'public'
    ACCESS_LEVEL_CONSORTIUM = 'consortium'
    ACCESS_LEVEL_PROTECTED = 'protected'
    DATASET_STATUS_PUBLISHED = 'published'

    # Special case used by file assets status only
    if uuid == 'status':
        return allowed

    # request.headers may or may not contain the 'Authorization' header
    final_request = request

    # We'll get the parent entity uuid if the given uuid is indeed a file uuid
    # If the given uuid is actually an entity uuid, just return it
    try:
        entity_uuid, entity_is_avr, given_uuid_is_file_uuid = get_entity_uuid_by_file_uuid(uuid)

        print(f"The given uuid {uuid} is a file uuid: {given_uuid_is_file_uuid}")

        if given_uuid_is_file_uuid:
            print(f"The parent entity_uuid: {entity_uuid}")
            print(f"The entity is AVR: {entity_is_avr}")
    except requests.exceptions.RequestException:
        # We'll just handle 400 and all other cases all together here as 500
        # because nginx auth_request only handles 200/401/403/500
        return internal_error

    # By now, the given uuid is either a real entity uuid
    # or we found the associated parent entity uuid of the given file uuid
    # If the given uuid is an AVR entity uuid (should not happen in normal situation), 
    # it'll go through but 404 returned by the assets nginx 
    # since we don't have any files for this AVR entity
    # If an AVR file uuid, we'll allow the access too and send back the file content
    # No token ever required regardless the given uuid is an AVR entity uuid or AVR file uuid
    if entity_is_avr:
        return allowed

    # For non-AVR entities:
    # Next to determine the data access level of the given uuid by 
    # making a call to entity-api to retrieve the entity first
    entity_api_full_url = ENTITY_API_URL + '/entities/' + entity_uuid

    # Function cache to improve performance
    # Possible response status codes: 200, 401, and 500 to be handled below
    response = make_api_request_get(entity_api_full_url)

    # Using the globus app secret as internal token should always return 200 supposedly
    # If not, either technical issue 500 or something wrong with this internal token 401
    if response.status_code == 200:
        entity_dict = response.json()

        # Won't happen in normal situations, but nice to check
        if 'entity_type' not in entity_dict:
            print(f"Missing 'entity_type' from returned result of entity uuid {entity_uuid}")
            return internal_error

        entity_type = entity_dict['entity_type']

        # The assets service only supports:
        # - Data files contained within a Dataset
        # - Thumbnail file (metadata) for Dataset 
        # - Image and metadata files (metadata) for Sample
        # - Image files (metadata) for Donor
        # - Standalone AVR files (PDF or word doc)
        if entity_type not in supported_entity_types:
            print(f"Unsupported 'entity_type' {entity_type} from returned result of entity uuid {entity_uuid}")
            return bad_request

        # Won't happen in normal situations, but nice to check
        if 'data_access_level' not in entity_dict:
            print(f"Missing 'data_access_level' from returned result of entity uuid {entity_uuid}")
            return internal_error

        # Default
        data_access_level = entity_dict['data_access_level']

        print(f"======data_access_level returned by entity-api for {entity_type} uuid {entity_uuid}======")
        print(data_access_level)

        # Donor and Sample `data_access_level` value can only be either "public" or "consortium"
        # Dataset has the "protected" data_access_level due to PHI `contains_human_genetic_sequences`
        # Use `status` to determine the access of Dataset attached thumbnail file (considered as metadata)
        # But the data files contained within the dataset is determined by `data_access_level`
        # A dataset with `status` "Published" (thumbnail file is public accessible) can have 
        # "protected" `data_access_level` (data files within the dataset are protected)
        if (entity_type == 'Dataset') and given_uuid_is_file_uuid and (
                entity_dict['status'].lower() == DATASET_STATUS_PUBLISHED):
            # Overwrite the default value
            data_access_level = ACCESS_LEVEL_PUBLIC

            print(f"======determined data_access_level for dataset attached thumbnail file uuid {uuid}======")
            print(data_access_level)

        # Throw error 500 if invalid access level value assigned to the dataset
        if data_access_level not in [ACCESS_LEVEL_PUBLIC, ACCESS_LEVEL_CONSORTIUM, ACCESS_LEVEL_PROTECTED]:
            print("The 'data_access_level' value of this dataset " + entity_uuid + " is invalid")
            return internal_error

        # Get the user access level based on token (optional) from HTTP header or query string
        # The globus token can be specified in the 'Authorization' header OR through a "token" query string in the URL
        # Use the globus token from URL query string if present and set as the value of 'Authorization' header
        # If not found, default to the 'Authorization' header
        # Because auth_helper_instance.getUserDataAccessLevel() checks against the 'Authorization' header
        if token_from_query is not None:
            # NOTE: request.headers is type 'EnvironHeaders', 
            # and it's immutable(read only version of the headers from a WSGI environment)
            # So we can't modify the request.headers
            # Instead, we use a custom request object and set as the 'Authorization' header 
            print("======set Authorization header with query string token value======")

            custom_headers_dict = create_request_headers_for_auth(token_from_query)

            # Overwrite the default final_request
            # CustomRequest and Flask's request are different types,
            # but the Commons's AuthHelper only access the request.headers
            # So as long as headers from CustomRequest instance can be accessed with the dot notation
            final_request = CustomRequest(custom_headers_dict)

        # By now, request.headers may or may not contain the 'Authorization' header
        print("======file_auth final_request.headers======")
        print(final_request.headers)

        # When Authorization is not present, return value is based on the data_access_level of the given dataset
        # In this case we can't call auth_helper_instance.getUserDataAccessLevel() because it returns HTTPException
        # when Authorization header is missing
        if 'Authorization' not in final_request.headers:
            # Return 401 if the data access level is consortium or protected since
            # they require token but Authorization header missing
            if data_access_level != ACCESS_LEVEL_PUBLIC:
                return authentication_required
            # Only return 200 since public dataset doesn't require token
            return allowed

        # By now the Authorization is present and it's either provided directly from the request headers or
        # query string (overwriting)
        # Then we can call auth_helper_instance.getUserDataAccessLevel() to find out the user's assigned access level
        try:
            # The user_info contains HIGHEST access level of the user based on the token
            # Default to ACCESS_LEVEL_PUBLIC if none of the Authorization/Mauthorization header presents
            # This call raises an HTTPException with a 401 if any auth issues are found
            user_info = auth_helper_instance.getUserDataAccessLevel(final_request)

            print("======user_info======")
            print(json.dumps(user_info, indent=4))
        # If returns HTTPException with a 401, invalid header format or expired/invalid token
        except HTTPException as e:
            msg = "HTTPException from calling auth_helper_instance.getUserDataAccessLevel() HTTP code: " + str(
                e.get_status_code()) + " " + e.get_description()

            print(msg)

            # In the case of requested dataset is public but provided globus token is invalid/expired,
            # we'll return 401 so the end user knows something wrong with the token rather than allowing file access
            return authentication_required

        # By now the user_info is returned and based on the logic of auth_helper_instance.getUserDataAccessLevel(), 
        # 'data_access_level' should always be found user_info and its value is always one of the 
        # ACCESS_LEVEL_PUBLIC, ACCESS_LEVEL_CONSORTIUM, or ACCESS_LEVEL_PROTECTED
        # So no need to check unknown value
        user_access_level = user_info['data_access_level'].lower()

        # By now we have both data_access_level and the user_access_level obtained with one of the valid values
        # Allow file access as long as data_access_level is public, no need to care about the
        # user_access_level (since Authorization header presents with valid token)
        if data_access_level == ACCESS_LEVEL_PUBLIC:
            return allowed

        # When data_access_level is consortium, allow access only when the user_access_level
        # (remember this is the highest level) is consortium or protected
        if (data_access_level == ACCESS_LEVEL_CONSORTIUM and
                (user_access_level == ACCESS_LEVEL_PROTECTED or user_access_level == ACCESS_LEVEL_CONSORTIUM)):
            return allowed

        # When data_access_level is protected, allow access only when user_access_level is also protected
        if data_access_level == ACCESS_LEVEL_PROTECTED and user_access_level == ACCESS_LEVEL_PROTECTED:
            return allowed

        # All other cases
        return authorization_required
    # Something wrong with fulfilling the request with secret as token
    # E.g., for some reason the gateway returns 401
    elif response.status_code == 401:
        print(f"Couldn't authenticate the request made to {entity_api_full_url} with internal token")
        return authorization_required
    elif response.status_code == 404:
        print(f"Unable to find uuid {entity_uuid}")
        return not_found
    # All other cases with 500 response
    else:
        print(f"Failed to get the access level of entity with uuid {entity_uuid}")
        return internal_error


# If the given uuid is a file uuid, get the parent entity uuid
# If the given uuid itself is an entity uuid, just return it
# The bool entity_is_avr is returned as a flag
# The bool given_uuid_is_file_uuid is returned as a flag
def get_entity_uuid_by_file_uuid(uuid):
    entity_uuid = None
    # Assume the target entity is NOT AVR record by default
    entity_is_avr = False
    # Assume the given uuid is a file uuid by default
    given_uuid_is_file_uuid = True

    # First determine if the given uuid is whether an entity uuid or a file uuid
    # by making a call to the uuid-api's /file-id endpoint
    uuid_api_file_url = f"{UUID_API_URL}/file-id/{uuid}"

    # Function cache to improve performance
    response = make_api_request_get(uuid_api_file_url)

    # 200: this given uuid is a file uuid
    # 404: either the given uuid does not exist or it's not a file uuid
    if response.status_code == 200:
        file_uuid_dict = response.json()

        if 'ancestor_uuid' in file_uuid_dict:
            print(f"======The given uuid {uuid} is a file uuid======")

            # For file uuid, its ancestor_uuid (the parent_id when generating this file uuid)
            # is the actual entity uuid that can be used to get back the data_access_level
            # Overwrite the default value
            entity_uuid = file_uuid_dict['ancestor_uuid']
        else:
            print(f"Missing 'ancestor_uuid' from resulting json for the given file_uuid {uuid}")

            raise requests.exceptions.RequestException(response.text)
    elif response.status_code == 404:
        # It could be a regular entity uuid but will return 404 by /file-id/<uuid>
        # We just log this and move forward
        # The call to entity-api will tell us if this dataset uuid exists and valid
        print(f"======Unable to find the file uuid: {uuid}, consider it as an entity uuid======")

        # Treat the given uuid as an entity uuid
        entity_uuid = uuid

        # Overwrite the default value
        given_uuid_is_file_uuid = False
    else:
        # uuid-api returns 400 if the given id is invalid
        msg = f"Unable to make a request to query the uuid via uuid-api: {uuid}"
        # Log the full stack trace, prepend a line with our message
        print(msg)

        print("======status code from uuid-api======")
        print(response.status_code)

        print("======response text from uuid-api======")
        print(response.text)

        # Also bubble up the error message from uuid-api
        raise requests.exceptions.RequestException(response.text)

    # Further check the entity type registered with uuid-api to determine if it's AVR or not
    # Make the call against the /uuid endpoint
    uuid_api_entity_url = f"{UUID_API_URL}/uuid/{entity_uuid}"

    # Function cache to improve performance
    response = make_api_request_get(uuid_api_entity_url)

    if response.status_code == 200:
        entity_uuid_dict = response.json()

        if 'type' in entity_uuid_dict:
            if entity_uuid_dict['type'].upper() == 'AVR':
                print(f"======The target entity_uuid {entity_uuid} is an AVR uuid======")

                entity_is_avr = True
        else:
            print(f"Missing 'type' from resulting json for the target entity_uuid {entity_uuid}")

            raise requests.exceptions.RequestException(response.text)
    else:
        msg = f"Unable to make a request to query the target entity uuid via uuid-api: {entity_uuid}"
        # Log the full stack trace, prepend a line with our message
        print(msg)

        print("======status code from uuid-api======")
        print(response.status_code)

        print("======response text from uuid-api======")
        print(response.text)

        # Also bubble up the error message from uuid-api
        raise requests.exceptions.RequestException(response.text)

    # Return the entity uuid string, if the entity is AVR, and 
    # if the given uuid is a file uuid or not (bool)
    return entity_uuid, entity_is_avr, given_uuid_is_file_uuid
