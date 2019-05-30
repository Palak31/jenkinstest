import boto3
import hmac
import hashlib
import base64
import botocore.exceptions
from chalicelib.logger import Logger
from chalicelib.exitStatus import ExitStatus, ExitMessage
import chalicelib.constants

clientkms = boto3.client('kms')
client = boto3.client('cognito-idp')
logger = Logger.initLogger()

def getUserPoolId(userpool_name):
    try:
        response = client.list_user_pools(MaxResults=60)
        logger.info(response)
        for key in response['UserPools'][:]:
            if key['Name']==userpool_name:
                print("Returning UserId:"+key['Id']+" for Username:"+key['Name'])
                return(key['Id'])
        while "NextToken" in response:
            response = client.list_user_pools(NextToken=response["NextToken"], MaxResults=60)
            logger.info(response)
            for key in response['UserPools'][:]:
                if key['Name']==userpool_name:
                    print("Returning UserPoolId:"+key['Id']+" for Username:"+key['Name'])
                    return(key['Id'])          
        return ""
        
    except client.exceptions.NotAuthorizedException as e:
        logger.error("Invalid token, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
    except Exception as e:
        logger.error("Failed to get Userpool Id, exception : %s",str(e))
        return {'exitCode':ExitStatus.ERROR,'message':str(e)}

def getSignedInUserType(token):
    try:
        response = client.get_user(AccessToken=token)
        logger.info(response)
        for item in response['UserAttributes']:
            if (item['Name'] == "custom:usertype"):
				print("Returning Usertype: "+item['Value'])
				return item['Value']
    except Exception as e:
        logger.error("Failed to get UserType, exception : %s",str(e))
        return {'exitCode':ExitStatus.ERROR,'message':str(e)}


def getUserType(pool_id, user_name):
	try:
		response = client.admin_get_user(
			UserPoolId=pool_id,
			Username= user_name
		)
        #logger.debug(response)
		for item in response['UserAttributes']:
			if (item['Name'] == "custom:usertype"):
				print("Returning Usertype: "+item['Value']+" for user "+user_name)
				return item['Value']
	except Exception as e:
		logger.error("Failed to get UserType, exception : %s",str(e))
		return {'Status':ExitStatus.ERROR,'message':str(e)}

def isValid(par):
    for param in par:
        if(par[param]==None or par[param]==''):
            return ExitStatus.ERR_EMPTY_PARAMS
    return ExitStatus.SUCCESS

def getAppClientId(pool_id):
    response = client.list_user_pool_clients(
         UserPoolId=pool_id
         )
    if response['UserPoolClients'] is []:
         return ""  # no pool in the system
    else:
         return response['UserPoolClients'][0]['ClientId']
    return ""

def getUserPoolSchema():
    userPoolSchema=[
            {
                'Name': 'email',
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': True,
                'NumberAttributeConstraints': {
                    'MinValue': '2',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '2',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'name',   #user fisrtname
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            
            {
                'Name': 'country',             # user country
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    }
            },
            {
                'Name': 'middle_name',    # user middlename
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'family_name',    #user lastName
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'zoneinfo',       # zoneinfo use as timeZone
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
     
            {
                'Name': 'companyname',       # companyName 
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'jobtitle',       # jobTitle 
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'usertype',       # userType 
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '2',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'webPage',       # userType 
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
            {
                'Name': 'aboutme',       # userType 
                'AttributeDataType': 'String',
                'DeveloperOnlyAttribute': False,
                'Mutable': True,
                'Required': False,
                'NumberAttributeConstraints': {
                    'MinValue': '0',
                    'MaxValue': '256'
                },
                'StringAttributeConstraints': {
                    'MinLength': '0',
                    'MaxLength': '256'
                    
                }
            },
        ]
    return userPoolSchema

def groupAuthorizer(userPoolId, token, role):
    global client
    response = ''
    logger = Logger.initLogger()
    response1 = client.list_users(
                                     UserPoolId=userPoolId,
                                    Limit=50
 
            )
    try:
        response = client.get_user(
                                     AccessToken=token
                                     )
    
    except client.exceptions.NotAuthorizedException as e:
        logger.error("Invalid token, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
    except client.exceptions.ResourceNotFoundException as e:
        logger.error("Invalid token, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
    except Exception as e:
		    logger.error("Failed to get UserType, exception : %s",str(e))
		    return {'exitCode':ExitStatus.ERROR,'message':str(e)}
   
    flag = 0
    user ={}
    while(flag==0):
        for user in response1['Users']:
            if(response['Username'] == user['Username']):
                for type in response['UserAttributes']:
                    if (type['Name'] == "custom:usertype" and (( type['Value'] == role or role == 'user') or (type['Value'] == 'adpayer' and role == 'payer'))):
                        return { 'Status': ExitStatus.SUCCESS, 'Message': ExitMessage.MSG_SUCCESS}
                    else:
                        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
                        
        if('PaginationToken' in response1 and flag == 0):
            response1 = client.list_users(
                                     UserPoolId=userPoolId,
                                    Limit=3,
                                    PaginationToken= response['PaginationToken']
 
            )
        else:
             return {'Status':ExitStatus.ERR_USER_NOT_EXIST,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}
        
#encrypt plaintext
def encryptCode(plain_text):
    try:
        byte_plain_text = plain_text.encode('ASCII') 
        response = clientkms.encrypt(
            KeyId= chalicelib.constants.CHIPER_KEY,
            Plaintext= byte_plain_text,
        )
    
        bs64 = base64.b64encode(response[u'CiphertextBlob'])
        return bs64.decode()
    except Exception as e:
        logger.error("Failed to get UserType, exception : %s",str(e))
        return {'exitCode':ExitStatus.ERROR,'message':"you are not allowed to perform this operation"}


#decrypt to  plaintext
def decryptCode(cipher_text):
    try:
        bs64 = base64.b64decode(cipher_text) 
        response = clientkms.decrypt(
            CiphertextBlob= bs64
        )
        return response[u'Plaintext'].decode()
    except Exception as e:
        logger.error("Failed to get UserType, exception : %s",str(e))
        return {'exitCode':ExitStatus.ERROR,'message':"you are not allowed to perform this operation"}

def list_users(pool_id,next_token=''):
    if(next_token==''):
         response = client.list_users(UserPoolId=pool_id,AttributesToGet=['email'],Limit=60)
    else:
         response = client.list_users(UserPoolId=pool_id,AttributesToGet=['email'],Limit=60,NextToken=next_token)
    return response


def getUsernameFromEmail(pool_id,members):
    try:
        response=list_users(pool_id)
        
        # UserName corresponds to Cognito stored hashed UserName
        # replace user email with corresponding username if user is valid
        # else it remains in the username_list , this is done so that 
        # wherever this list is used to do operation like addUserToProject
        # it can throw user not found error
        username_list = list(members)
        while True:
            for user in response['Users']:
                if(user['Attributes'][0]['Value'] in members):
                    index_of_email=members.index(user['Attributes'][0]['Value'])
                    username_list[index_of_email]=str(user['Username'])
        
            next_token=response.get('NextToken','')
            
            if(next_token!=''):
                response=list_users(pool_id,next_token)
                app.log.debug(response)
            else:
                break
        
        return {'Status' :ExitStatus.SUCCESS,'usernames':username_list}
        
    
    except client.exceptions.InvalidParameterException as e:
        #app.log.error("Fail to get username from email, exception : %s",str(e))
        return {'Status' :ExitStatus.ERR_INVALID_PARAMS,'message':'invalid parameters'}
        
    except client.exceptions.ResourceNotFoundException as e:
        #app.log.error("Fail to get username from email : %s",str(e))
        return {'Status' :ExitStatus.ERR_RES_NOT_FOUND,'message':'could not find pool id'}
        
    except Exception as e:
        #app.log.error("Fail to get username from email : %s",str(e))
        return {'Status' :ExitStatus.ERROR,'message':str(e)}
        
        
#notification related utility function: get user from access_token
def getMembername(access_token):
    try:
        response = client.get_user(
            AccessToken=token
            )
        return response['Username']
    except client.exceptions.NotAuthorizedException as e:
        logger.error("Invalid token, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
    except client.exceptions.ResourceNotFoundException as e:
        logger.error("Invalid token, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
    except Exception as e:
		    logger.error("Failed to get UserType, exception : %s",str(e))
		    return {'exitCode':ExitStatus.ERROR,'message':str(e)}