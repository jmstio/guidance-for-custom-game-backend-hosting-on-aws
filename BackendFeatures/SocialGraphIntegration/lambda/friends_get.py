# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import json, os, boto3, sys, backoff
from gremlin_python import statics
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
from gremlin_python.driver.protocol import GremlinServerError
from gremlin_python.driver import serializer
from gremlin_python.process.anonymous_traversal import traversal
from gremlin_python.process.graph_traversal import __
from gremlin_python.process.strategies import *
from gremlin_python.process.traversal import T, P, Order, Scope, Column
from aiohttp.client_exceptions import ClientConnectorError
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import ReadOnlyCredentials
from types import SimpleNamespace

from aws_lambda_powertools import Tracer
from aws_lambda_powertools import Logger
tracer = Tracer()
logger = Logger()

reconnectable_err_msgs = [ 
    'ReadOnlyViolationException',
    'Server disconnected',
    'Connection refused',
    'Connection was already closed',
    'Connection was closed by server',
    'Failed to connect to server: HTTP Error code 403 - Forbidden'
]

retriable_err_msgs = ['ConcurrentModificationException'] + reconnectable_err_msgs

network_errors = [OSError, ClientConnectorError]

retriable_errors = [GremlinServerError, RuntimeError, Exception] + network_errors      

def error_response(message, code):
    return {
        "statusCode": code,
        "body": json.dumps(message),
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': True
        },
    }

def prepare_iamdb_request(database_url):
    logger.info('Preparing IAMDB request')
    service = 'neptune-db'
    method = 'GET'

    access_key = os.environ['AWS_ACCESS_KEY_ID']
    secret_key = os.environ['AWS_SECRET_ACCESS_KEY']
    region = os.environ['AWS_REGION']
    session_token = os.environ['AWS_SESSION_TOKEN']
    
    creds = SimpleNamespace(
        access_key=access_key, secret_key=secret_key, token=session_token, region=region,
    )

    request = AWSRequest(method=method, url=database_url, data=None)
    SigV4Auth(creds, service, region).add_auth(request)
    
    return (database_url, request.headers)
        
def is_retriable_error(e):

    is_retriable = False
    err_msg = str(e)
    
    if isinstance(e, tuple(network_errors)):
        is_retriable = True
    else:
        is_retriable = any(retriable_err_msg in err_msg for retriable_err_msg in retriable_err_msgs)
    
    logger.error('error: [{}] {}'.format(type(e), err_msg))
    logger.info('is_retriable: {}'.format(is_retriable))
    
    return is_retriable

def is_non_retriable_error(e):      
    return not is_retriable_error(e)
        
def reset_connection_if_connection_issue(params):
    
    is_reconnectable = False

    e = sys.exc_info()[1]
    err_msg = str(e)
    
    if isinstance(e, tuple(network_errors)):
        is_reconnectable = True
    else:
        is_reconnectable = any(reconnectable_err_msg in err_msg for reconnectable_err_msg in reconnectable_err_msgs)
        
    logger.info('is_reconnectable: {}'.format(is_reconnectable))
        
    if is_reconnectable:
        global conn
        global g
        conn.close()
        conn = create_remote_connection()
        g = create_graph_traversal_source(conn)
     
@backoff.on_exception(backoff.constant,
    tuple(retriable_errors),
    max_tries=5,
    jitter=None,
    giveup=is_non_retriable_error,
    on_backoff=reset_connection_if_connection_issue,
    interval=1)
def query(**kwargs):
    
    queryString = kwargs['queryString']

    # { id = '<PLAYER_ID>', dir = ['in'|'out'|'new'], max='[<MAX_COUNT>]'}
    if 'id' not in queryString:
        logger.error('id parameter is missing.')
        raise KeyError('id parameter is missing.')
    player_id = queryString['id']
    
    player_v = g.V(player_id).toList()
    if not player_v:
        logger.error('Player {} does not exist.', format(player_id))
        raise ValueError('Player {} does not exist.'.format(player_id))

    friend_dir = 'out'
    if 'dir' in queryString:
        friend_dir = str.lower(queryString['dir'])

    max_count = 10
    if 'max' in queryString:
        max_count = int(queryString['max'])

    logger.info('Getting friends of player {}, direction {}'.format(player_id, dir))
    match (friend_dir):
        case 'in':
            result = g.V(player_id).inE('friendWith').out_v().hasLabel('player').dedup().toList()[0:max_count]
        case 'out':
            result = g.V(player_id).outE('friendWith').in_v().hasLabel('player').dedup().toList()[0:max_count]
        case 'new':
            result = g.V(player_id).as_('user').out('friendWith').aggregate('friends').both('friendWith').where(P.neq('user')).where(P.without(['friends'])).groupCount().by(T.id_).order(Scope.local).by(Column.values,Order.desc).unfold().toList()[0:max_count]
        case _:
            logger.error('Invalid direction {}'.format(friend_dir))
            raise ValueError('Invalid direction {}'.format(friend_dir))
    
    return result
        
def doQuery(event):
    logger.info('Event received: {}'.format(event))

    if 'queryStringParameters' not in event:
        logger.error('querystring parameter is missing.')
        raise KeyError('querystring parameter is missing.')
    
    queryString = event['queryStringParameters']

    return query(queryString=queryString)

@tracer.capture_lambda_handler
def lambda_handler(event, context):
    try:
        result = doQuery(event)
        logger.info('Result: {}'.format(result))

        return {
            "statusCode": 200,
            "body": json.dumps(result, default=str),
            'headers': {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Credentials': True
            }
        }
    except Exception as err:
        logger.error('Unexpected {}: {}'.format(type(err), str(err)))
        return error_response(str(err), 500)
    
def create_graph_traversal_source(conn):
    return traversal().withRemote(conn)
    
def create_remote_connection():
    logger.info('Creating remote connection')
    
    (database_url, headers) = connection_info()
    
    return DriverRemoteConnection(
        database_url,
        'g',
        pool_size=1,
        message_serializer=serializer.GraphSONSerializersV2d0(),
        headers=headers)
    
def connection_info():
    
    database_url = 'wss://{}/gremlin'.format(os.environ['NEPTUNE_ENDPOINT'])
    
    if 'USE_IAM' in os.environ and os.environ['USE_IAM'] == 'true':
        return prepare_iamdb_request(database_url)
    else:
        return (database_url, {})
    
conn = create_remote_connection()
g = create_graph_traversal_source(conn)