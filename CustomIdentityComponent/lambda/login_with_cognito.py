import json
import os
import uuid
import boto3
import requests
import jwt  # Using PyJWT to decode the token
from botocore.config import Config
from aws_lambda_powertools import Tracer, Logger, Metrics, single_metric
from aws_lambda_powertools.metrics import MetricUnit
from jwt.algorithms import RSAAlgorithm
from encryption_and_decryption import encrypt, decrypt

# Initialize clients and logger
tracer = Tracer()
logger = Logger()
metrics = Metrics()
metrics.set_default_dimensions(function=os.environ['AWS_LAMBDA_FUNCTION_NAME'])
config = Config(connect_timeout=2, read_timeout=2)
dynamodb = boto3.resource('dynamodb')
user_table = dynamodb.Table(os.environ['USER_TABLE'])
client = boto3.client('cognito-idp')

# Cognito configuration
CognitoIssuer = f"https://cognito-idp.eu-central-1.amazonaws.com/{os.environ['COGNITO_USER_POOL_ID']}"
jwks_url = f"{CognitoIssuer}/.well-known/jwks.json"
app_client_id = os.environ['COGNITO_APP_CLIENT_ID']

# Token expiration times
access_token_expiration = 900  # 15 minutes
refresh_token_expiration_days = 6  # 6 days

# Helper function to create a response
@tracer.capture_method
def create_response(status_code, message):
    return {
        "statusCode": status_code,
        "body": json.dumps(message),
        "headers": {"Content-Type": "application/json"}
    }

# Helper function to log metrics
@tracer.capture_method
def log_metric(name, unit=MetricUnit.Count, value=1, reason=None):
    if reason:
        with single_metric(name=name, unit=unit, value=value, default_dimensions=metrics.default_dimensions) as metric:
            metric.add_dimension(name="reason", value=reason)
    else:
        metrics.add_metric(name=name, unit=unit, value=value)

# Helper function to handle DynamoDB operations
@tracer.capture_method
def handle_dynamodb_operation(table_name, operation, **kwargs):
    table = dynamodb.Table(table_name)
    try:
        if operation == 'put':
            table.put_item(**kwargs)
        elif operation == 'get':
            return table.get_item(**kwargs)
        elif operation == 'update':
            table.update_item(**kwargs)
        return True
    except Exception as e:
        logger.error(f"DynamoDB operation failed: {e}")
        return False

# Helper function to verify JWT
@tracer.capture_method
def verify_jwt(token):
    try:
        jwks = requests.get(jwks_url).json()
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']
        rsa_key = next((key for key in jwks['keys'] if key['kid'] == kid), None)
        if not rsa_key:
            raise Exception("Public key not found in JWKS")
        public_key = RSAAlgorithm.from_jwk(json.dumps(rsa_key))
        payload = jwt.decode(
            token,
            public_key,
            algorithms=['RS256'],
            options={"require": ["exp", "iss", "sub"], "verify_aud": True, "verify_signature": True, "verify_issuer": True},
            issuer=CognitoIssuer
        )
        return payload
    except Exception as e:
        raise Exception(f"Token verification failed: {e}")

# Helper function to handle Cognito operations
@tracer.capture_method
def handle_cognito_operation(operation, **kwargs):
    try:
        if operation == 'initiate_auth':
            return client.initiate_auth(**kwargs)
        elif operation == 'sign_up':
            return client.sign_up(**kwargs)
        elif operation == 'confirm_sign_up':
            return client.confirm_sign_up(**kwargs)
        elif operation == 'global_sign_out':
            return client.global_sign_out(**kwargs)
        elif operation == 'forgot_password':
            return client.forgot_password(**kwargs)
        elif operation == 'confirm_forgot_password':
            return client.confirm_forgot_password(**kwargs)
    except Exception as e:
        logger.error(f"Cognito operation failed: {e}")
        return None

@metrics.log_metrics
@tracer.capture_lambda_handler
def lambda_handler(event, context):
    event_body = json.loads(event['body'])
    username = event_body.get('username')
    password = event_body.get('password')
    email = event_body.get('email')
    signin = event_body.get('signin')
    signup = event_body.get('signup')
    signup_confirmation_code = event_body.get('confirmation_code')
    signout = event_body.get('signout')
    forgot_password = event_body.get('forgot_password')
    reset_password = event_body.get('reset_password')
    reset_password_code = event_body.get('reset_password_code')
    access_token = event_body.get('access_token')

    if signup == "True":
        auth_result = handle_cognito_operation('sign_up', ClientId=app_client_id, Username=username, Password=password, UserAttributes=[{'Name': 'email', 'Value': email}])
        if auth_result is None:
            return create_response(400, "Cognito Sign Up failed")
        message = "Cognito Sign Up successful, please confirm your code" if 'UserConfirmed' in auth_result and not auth_result['UserConfirmed'] else "Cognito Sign Up successful"
        return create_response(200, message)

    if signup_confirmation_code:
        auth_result = handle_cognito_operation('confirm_sign_up', ClientId=app_client_id, Username=username, ConfirmationCode=signup_confirmation_code)
        return create_response(200, "Cognito Confirmation successful") if auth_result else create_response(400, "Cognito Confirmation failed")

    if forgot_password == "True":
        auth_result = handle_cognito_operation('forgot_password', ClientId=app_client_id, Username=username)
        return create_response(200, "Cognito Forgot Password successful") if auth_result else create_response(400, "Cognito Forgot Password failed")

    if reset_password == "True":
        auth_result = handle_cognito_operation('confirm_forgot_password', ClientId=app_client_id, Username=username, ConfirmationCode=reset_password_code, Password=password)
        return create_response(200, "Cognito Reset Password successful") if auth_result else create_response(400, "Cognito Reset Password failed")

    if signout == "True" and access_token:
        auth_result = handle_cognito_operation('global_sign_out', AccessToken=access_token)
        return create_response(200, "Cognito Sign Out successful") if auth_result else create_response(400, "Cognito Sign Out failed")

    if signin == "True":
        auth_result = handle_cognito_operation('initiate_auth', ClientId=app_client_id, AuthFlow='USER_PASSWORD_AUTH', AuthParameters={'USERNAME': username, 'PASSWORD': password})
        if not auth_result:
            return create_response(400, "Cognito SignIn failed, no user found")
        cognito_access_token = auth_result.get('AuthenticationResult', {}).get('AccessToken')
        if not cognito_access_token:
            return create_response(400, "Cognito Access Token is missing from the auth response")

        try:
            verified_claims = verify_jwt(cognito_access_token)
            cognito_user_id = verified_claims['sub']
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return create_response(401, "Invalid or expired access token")

        success, user_id = get_existing_user(cognito_user_id)
        if not success:
            log_metric('failure', reason='Failed the try getting existing user')
            return create_response(400, 'Error: Failed the try getting existing user')

        if not user_id:
            query_params = event.get('queryStringParameters', {})
            if query_params.get('auth_token') and query_params.get('link_to_existing_user') == "Yes":
                decoded_backend_token = decrypt(query_params['auth_token'])
                if not decoded_backend_token:
                    log_metric('failure', reason='Failed to authenticate with existing identity')
                    return create_response(400, 'Error: Failed to authenticate with existing identity')
                user_id = decoded_backend_token['sub']
                success = link_cognito_id_to_existing_user(user_id, cognito_user_id)
                if not success:
                    log_metric('failure', reason='Failed to link new user to existing user')
                    return create_response(400, 'Error: Failed to link new user to existing user')
            else:
                logger.info("No user yet, creating a new one")
                tries = 0
                while not user_id and tries < 10:
                    user_id = create_user(cognito_user_id)
                    tries += 1
                if not user_id:
                    log_metric('failure', reason='Failed to create user')
                    return create_response(400, 'Error: Failed to create user')

            add_new_user_to_cognito_table(user_id, cognito_user_id)

        payload = {'sub': user_id}
        auth_token, refresh_token, auth_token_expires_in, refresh_token_expires_in = encrypt(payload, "authenticated")
        log_metric('success')
        return create_response(200, {
            'user_id': user_id,
            'cognito_id': cognito_user_id,
            'auth_token': auth_token,
            'refresh_token': refresh_token,
            'auth_token_expires_in': auth_token_expires_in,
            'refresh_token_expires_in': refresh_token_expires_in
        })

    log_metric('failure', reason='Invalid request')
    return create_response(400, 'Error: Failed to authenticate')

# Helper function to get existing user
@tracer.capture_method
def get_existing_user(cognito_id):
    try:
        cognito_user_table_name = os.getenv("COGNITO_USER_TABLE")
        response = handle_dynamodb_operation(cognito_user_table_name, 'get', Key={'CognitoId': cognito_id})
        if 'Item' in response:
            logger.info("Found existing user in Cognito ID table:", user_id=response['Item']['UserId'])
            return True, response['Item']['UserId']
        return True, None
    except Exception as e:
        logger.error("Exception reading from user table: ", exception=e)
    return False, None

# Helper function to create a new user
@tracer.capture_method
def create_user(cognito_user_id):
    user_id = str(uuid.uuid4())
    success = handle_dynamodb_operation(os.environ['USER_TABLE'], 'put', Item={'UserId': user_id, 'CognitoId': cognito_user_id}, ConditionExpression='attribute_not_exists(UserId)')
    if success:
        log_metric('created_user')
        return user_id
    logger.info("User already exists")
    return None

# Helper function to link Cognito ID to existing user
@tracer.capture_method
def link_cognito_id_to_existing_user(user_id, cognito_id):
    success = handle_dynamodb_operation(os.getenv("USER_TABLE"), 'update', Key={'UserId': user_id}, UpdateExpression="set CognitoId = :val1", ExpressionAttributeValues={':val1': cognito_id}, ConditionExpression='attribute_exists(UserId)')
    if success:
        log_metric('linked_user')
    return success

# Helper function to add new user to Cognito table
@tracer.capture_method
def add_new_user_to_cognito_table(user_id, cognito_id):
    success = handle_dynamodb_operation(os.getenv("COGNITO_USER_TABLE"), 'put', Item={'UserId': user_id, 'CognitoId': cognito_id})
    if success:
        log_metric('new_cognito_user')
    return success