from chalice import Chalice
from chalicelib.exitStatus import ExitStatus, ExitMessage
import chalicelib.utility 
import boto3
import botocore.exceptions
import json
import chalicelib.constants
import hmac
import hashlib
import base64
import ast
import requests



next_token=''
app = Chalice(app_name='jenkins_user')
app.debug = True

clientkms = boto3.client('kms')
client = boto3.client('cognito-idp')
userinfo={}

#login member
def loginMember(username,password,client_id, pool_id):
    try:
        response = client.admin_initiate_auth(
            AuthFlow= 'ADMIN_NO_SRP_AUTH',
            UserPoolId=pool_id,
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
                },
            ClientId=client_id
            )
        app.log.debug("User logged in successfully: %s",str(response))    
        return {"Status":ExitStatus.SUCCESS,"response":response}
       
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Member is not found, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_EXIST,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST} 
        
    except client.exceptions.InvalidParameterException as e:
        app.log.error("Fail to signIn user, exception : %s",str(e))
        return {'Status':ExitStatus.ERR_INVALID_PARAMS,'Message':ExitMessage.ERR_MSG_INVALID_PARAMS}
        
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to signIn user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}  
        
    except Exception as e:
        app.log.error("Fail to create team, exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'message':str(e)}


# login member 
@app.route('/login',methods=['POST'], cors=True)
def index():
    try:
        app.log.info("BEGIN: Login API")
        # Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to Sign In User: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        
        # Getting parameters from body
        username= request_body['email']
        password=request_body['password']
        #client_id=request_body['clientId']
        pool_name = request_body['teamName']
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
           app.log.error("Team does not exist , exception")
           return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST}   
           
        client_id = chalicelib.utility.getAppClientId(pool_id)
        if client_id == "":
           app.log.error("appclient does not exist , exception : %s",str(e))
           return "appclient does not exist"  
        #signed In user 
        login_member = loginMember(username,password,client_id,pool_id)
        if login_member['Status'] == ExitStatus.SUCCESS:
            return {"accessToken":str(login_member['response']['AuthenticationResult']['AccessToken'])}
        else:
            return login_member
            
    except KeyError as e:
            app.log.error('KeyError'+str(e))
            return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}   


'''
#To get admin count from team
def adminCount(pool_id):
    try:
     
        listed_member = listAllMember(pool_id,limit=50)
        count=0
        # Build the member list by taking only required attributes
        while True: 
            for user in listed_member['Users']:
                for attributes in user['Attributes']:
                    if attributes['Value'] == 'admin':
                        count= count+1
                    
            next_token= listed_member.get('PaginationToken','')
            if(next_token!=''):
                listed_member=listAllMemberToken(pool_id,next_token,limit=50)
            else:
                break
      
        return count

    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}

#confirm the member email using admin update
def confirmEmail(pool_id,username):
    try:
        response = client.admin_update_user_attributes(
            UserPoolId= pool_id,
            Username=  username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                },
            ]
        )
        app.log.debug("Member Email confirmed successfully: %s",str(response))  
        return {'Status':ExitStatus.SUCCESS,'Message':'Member created successfully'}
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to delete user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_EXIST,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}  
    
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to delete user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}
    
    except Exception as e:
        app.log.error("Fail to confirmed user , error: %s",str(e))
        return {'Status':ExitStatus.ERROR,'message':str(e)}

# confirm the user sign up. 
def confirmMember(pool_id,username):
    try:
        response = client.admin_confirm_sign_up(
            UserPoolId= pool_id,
            Username= username
            )
        
        app.log.debug("User confirmed successfully: %s",str(response))  
        return {'Status':ExitStatus.SUCCESS,'Message':str(response)+' User confirmed successfully'}
    except client.exceptions.UsernameExistsException as e:
        app.log.error("Fail to confirmed user , Username Exists: %s",str(e))
        return {'Status':ExitStatus.ERR_USER_ALREADY_EXISTS,'Message':ExitMessage.ERR_MSG_USER_ALREADY_EXIST}
    except Exception as e:
        app.log.error("Fail to confirmed user , error: %s",str(e))
        return {'Status':ExitStatus.ERROR,'message':str(e)}
        


# create a new member in the team (user pool)        
def createMember(username, password,user_attriutes,client_id):
    try:
        response = client.sign_up(
            ClientId=client_id,
            Username=username,
            Password=password,
            UserAttributes=user_attriutes
            )
        app.log.debug("Member "+username+" created successfully: %s",str(response))    
        return {'Status':ExitStatus.SUCCESS,'Message':'Member created successfully'}
    except client.exceptions.UsernameExistsException as e:
        app.log.error("Fail to signIn user , Username Exists: %s",str(e))
        return {'Status':ExitStatus.ERR_USER_ALREADY_EXIST,'Message':ExitMessage.ERR_MSG_USER_ALREADY_EXIST}
    except Exception as e:
        app.log.error("Fail to signIn user , error: %s",str(e))
        return {'Status':ExitStatus.ERROR,'message':str(e)}
    
#createMember API      
@app.route('/createMember',methods=['POST'], cors=True)
def index():
    try:
        app.log.info("BEGIN: createMember API")
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))

        if request_body['middleName'] == "" or None:
             request_body['middleName']= " "
        if request_body['country'] == "" or None:
             request_body['country']= " "
        if request_body['zoneInfo'] == "" or None:
             request_body['zoneInfo']= " "
        if request_body['company'] == "" or None:
             request_body['company']= " " 
        if request_body['jobTitle'] == "" or None:
             request_body['jobTitle']= " "
        if request_body['webPage'] == "" or None:
             request_body['webPage']= " "
        if request_body['aboutMe'] == "" or None:
             request_body['aboutMe']= " "     
        # Getting parameters from body
        username = request_body['email']
        password = request_body['password']
        user_attriutes = [
            {
                'Name':'email',
                'Value': request_body['email']
            },
            {
                'Name':'name',
                'Value': request_body['givenName']
            },
            {
                'Name':'custom:country',
                'Value': request_body['country']
            },
            {
                'Name':'middle_name',
                'Value': request_body['middleName']
            },
            {
                'Name':'family_name',
                'Value': request_body['familyName']
            },
            {
                'Name':'zoneinfo',
                'Value': request_body['zoneInfo']
            },
            {
                'Name':'custom:companyname',
                'Value': request_body['company']
            },
            {
                'Name':'custom:jobtitle',
                'Value': request_body['jobTitle']
            },
            {
                'Name':'custom:usertype',
                'Value': request_body['userType']
            },
            {
                'Name':'custom:webPage',
                'Value': request_body['webPage']
            }
            ]
            
        pool_name = request_body['teamName']
        team_encrypted = request_body['teamEncrypt']
        user_type = request_body['userType']
        if chalicelib.utility.decryptCode(team_encrypted) == pool_name+username:
            pool_id = chalicelib.utility.getUserPoolId(pool_name)
            if pool_id == "":
               app.log.error("Team does not exist , exception" )
               return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
            #getting admin count to check only one admin in team
            admin_count = adminCount(pool_id)
            if user_type == 'user' or admin_count == 0:
                client_id = chalicelib.utility.getAppClientId(pool_id)
                if client_id == "":
                    app.log.error("app client does not exist , exception ")
                    return {'Status':ExitStatus.ERROR,'Message':"App client does not exist(internal error)"}

                signed_up = createMember(username, password,user_attriutes,client_id)
                signup_confirmed = confirmMember(pool_id,username)
                email_confirmed=  confirmEmail(pool_id,username)
                
                #Add member entry in redis cache
                headers = {'content-type': 'application/json'}
                API_URL = chalicelib.constants.ADD_REDIS_MEMBER
                data = {
                    "redisMember":username+pool_name
                }
                response = requests.post(API_URL, data=json.dumps(data),headers=headers)
                res = json.loads(response.content)
                app.log.debug(" requests.post response= "+str(res))
                return signed_up
            else:
                return {'Status':ExitStatus.ERROR,'Message':"Admin alreday exists."}       
        else:
            return {'Status':ExitStatus.ERROR,'Message':"Not allowed to perform this operation, please contact admin."}
            
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}  
        


     
# delete member from team (user pool)
def deleteMember(pool_id,username):
    try:
        
        response = client.admin_delete_user(
            UserPoolId=pool_id,
            Username= username
            )
        app.log.debug("User deleted successfully : %s",str(response))
        return {'Status':ExitStatus.SUCCESS,'Message':'Member deleted successfully'}
    
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to delete user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_EXIST,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}
         
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to delete user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED} 
              
    except Exception as e:
        app.log.error("Failed to delete user , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}    
        
        
        
#deleteMember API        
@app.route('/deleteMember',methods=['DELETE'], cors=True)
def index():
    try:
        app.log.info("BEGIN: deleteMember API")   
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))

        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete User: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete user: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        
        # Getting parameters from body
        pool_name = request_body['teamName']
        username = request_body['email']
        access_token = request_header['Authorization']   
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
            app.log.error("Team does not exist , exception ")
            return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST}  
            
        user_type = chalicelib.utility.getUserType(pool_id, username)      
        admin_count = adminCount(pool_id)
        if user_type == 'user' or admin_count > 1:
            authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "admin")
            if(authorize['Status'] == ExitStatus.SUCCESS):  
                deleted_member= deleteMember(pool_id,username)
                
                #Delete redis member entry from cache
                headers = {'content-type': 'application/json'}
                API_URL = chalicelib.constants.DELETE_NOTIFICATION
                data = {
                    "member":username,
                    "teamName":pool_name
                }
                response = requests.post(API_URL, data=json.dumps(data),headers=headers)
                res = json.loads(response.content)
                app.log.debug(" requests.post response= "+str(res))
                return deleted_member
            else:
                return authorize
        else:
            return{"Status":ExitStatus.ERR_ONLY_ONE_ADMIN,'Message':ExitMessage.ERR_MSG_ONLY_ONE_ADMIN}   
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to delete user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_EXIST,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}  
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'message':str(e)}
 
        

#Member log using accessToken
def logoutUser(access_token):
    try:
        response = client.global_sign_out(
            AccessToken=access_token
            )
        app.log.debug("Member logged out successfully")
        return {'Status':ExitStatus.SUCCESS,'Message':'Member logged out successfully'}
        
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to logout member , exception : %s",str(e))
        return {'Status':ExitStatus.USER_NOT_FOUND,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to logout member , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED} 
    except Exception as e:
        app.log.error("Failed to logout member , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}  

#Member Logout API
@app.route('/logout',methods=['POST'], cors=True)
def index():
    try:
        app.log.info("BEGIN: Logout API")
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to logout member: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        
        # Getting parameters from body
        access_token = request_header['Authorization']     # authentication token of the caller generated by cognito
        pool_name = request_body['teamName']
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
            app.log.error("Team does not exist")
            return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST}   
        authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "user")  
        if(authorize['Status'] == ExitStatus.SUCCESS):  
            logout = logoutUser(access_token)
            return logout
        else:
            return authorize
            
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}  
    
        
#List all member information for the given member.
def findMember(pool_id,username):
    try:
        response = client.admin_get_user(
            UserPoolId=pool_id,
            Username=username
            )
        app.log.debug("user getted successfully: %s",str(response))
        #return response
        return {"Status":ExitStatus.SUCCESS,"response":response}
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to get user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_EXIST,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}
        
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to get user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED} 
            
    except Exception as e:
        app.log.error("Failed to get user , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}  
        
#findMember API
@app.route('/findMember',methods=['POST'], cors=True)
def index():
    try:
        app.log.info("BEGIN: findMember API")
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete User: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        # Getting parameters from body
        pool_name = request_body['teamName']
        username = request_body['email']
        access_token = request_header['Authorization']                # authentication token of the caller generated by cognito
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
           app.log.error("Team does not exist , exception")
           return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
        
        # call to authorizer to check if caller is authorized
        authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "user")
        
        if(authorize['Status'] == ExitStatus.SUCCESS):
            get_member= findMember(pool_id,username)
            if get_member["Status"] == ExitStatus.SUCCESS:
				        userinfo = get_member["response"]["UserAttributes"]
				        required_attributes= {
					          'family_name':'familyName',
					          'middle_name':'middleName',
					          'name':'givenName',
					          'email':'email',
					          'zoneinfo':'zoneInfo',
					          'custom:jobtitle':'jobTitle',
					          'custom:country':'country',
					          'custom:companyname':'company',
					          'custom:jobTitle':'jobTitle',
					          'custom:webPage':'webPage',
                    'custom:usertype':'userType',
                    'custom:aboutme':'aboutMe' 
				        }
				        current_attributes={}
				        for info in get_member["response"]["UserAttributes"]:
				            if(required_attributes.get(info['Name'],0)!=0):
						            current_attributes[required_attributes[info['Name']]]=info['Value']
				        return current_attributes
            else:
				        return get_member
        else:
            return authorize
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.KEY_ERROR,'Message':str(e)}  

        

# list all members of the team (user pool)  # To do : pagination
def listAllMember(pool_id,limit):
    try:
        response = client.list_users(
            UserPoolId=pool_id,
            AttributesToGet=[
                'email',
                'name',
                'middle_name',
                'family_name',
                'zoneinfo',
                'custom:companyname',
                'custom:country',
                'custom:jobtitle',
                'custom:usertype',
                'custom:webPage',
            ],
            Limit=limit
            )    
        app.log.debug("Members listed : %s",str(response))
        #return {"response":str(response)}
        return response
    except client.exceptions.InvalidParameterException as e:
        app.log.error("Fail to list user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_INVALID_PARAMS,'Message':ExitMessage.ERR_MSG_INVALID_PARAMS}
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to list user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}     
    except Exception as e:
        app.log.error("Fail to list user , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}
        
# list all members of the team (user pool) with pagination  # To do : pagination
def listAllMemberToken(pool_id,next_token,limit):
    try:
        response = client.list_users(
            UserPoolId=pool_id,
            AttributesToGet=[
                'email',
                'name',
                'middle_name',
                'family_name',
                'zoneinfo',
                'custom:companyname',
                'custom:country',
                'custom:jobtitle',
                'custom:usertype',
                'custom:webPage',
            ],
            Limit=limit,
            PaginationToken = next_token
            )    
        app.log.debug("Members listed with token: %s",str(response))
        return response
    except client.exceptions.InvalidParameterException as e:
        app.log.error("Fail to list user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_INVALID_PARAMS,'Message':ExitMessage.ERR_MSG_INVALID_PARAMS}
        
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to list user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}    
         
    except Exception as e:
        app.log.error("Fail to list user , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}
        
#listAllMember API       
@app.route('/listAllMember',methods=['PUT'], cors=True)
def index():
    try:
        app.log.info("BEGIN: listAllMember API")
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete User: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        # Getting parameters from body
        pool_name= request_body['teamName']
        access_token = request_header['Authorization']                  # authentication token of the caller generated by cognito
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
            app.log.error("Team does not exist , exception ")
            return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
        
        # call to authorizer to check if caller is authorized
        authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "user")
      
        if(authorize['Status'] == ExitStatus.SUCCESS):
            listed_member = listAllMember(pool_id,limit=50)
            users_list=[]
            required_attributes= {
                'family_name':'familyName',
                'middle_name':'middleName',
                'name':'givenName',
                'email':'email',
                'zoneinfo':'zoneInfo',
                'custom:jobtitle':'jobTitle',
                'custom:country':'country',
                'custom:companyname':'company',
                'custom:jobTitle':'jobTitle',
                'custom:webPage':'webPage',
                'custom:usertype':'userType',
                
                }
            # Build the member list by taking only required attributes
            while True:
                
                for user in listed_member['Users']:
                    current_attributes={}
                    for attributes in user['Attributes']:
                        if(required_attributes.get(attributes['Name'],0)!=0):
                            current_attributes[required_attributes[attributes['Name']]]=attributes['Value']
                    users_list.append((current_attributes))
                    
                #next_token= listed_member['PaginationToken']
                next_token= listed_member.get('PaginationToken','')
                if(next_token!=''):
                    listed_member=listAllMemberToken(pool_id,next_token,limit=50)
                else:
                    break
            return {"MemberList":json.loads(json.dumps(users_list))}
        else:
            return authorize
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}

# updated the member password
def updateMemberPassword(access_token,previous_password,proposed_password):
    try:
        response = client.change_password(
            PreviousPassword=previous_password,
            ProposedPassword=proposed_password,
            AccessToken=access_token
            )
        app.log.debug("password changed  successfully: %s",str(response))
        return {'Status':ExitStatus.SUCCESS,'Message':'Password updated successfully'}

    except client.exceptions.InvalidParameterException as e:
        app.log.error("Fail to change password  , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_INVALID_PARAMS,'Message':ExitMessage.ERR_MSG_INVALID_PARAMS}
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to  change password , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}    
    except client.exceptions.InvalidPasswordException as e:
        app.log.error("Fail to  change password , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_INVALID_OLD_PASSWORD,'Message':ERR_MSG_INVALID_OLD_PASSWORD}  
    except Exception as e:
        app.log.error("Fail to  change password , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'message':str(e)}  


#updatePassword API   
@app.route('/updatePassword',methods=['PUT'], cors=True)
def index():
    try:
        app.log.info("BEGIN: updatePassword API")
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete User: empty parameters")
            return {'Status':ExitStatus.ERR_EMPTY_PARAMS }
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'Status':ExitStatus.ERR_EMPTY_PARAMS }
            
        # Getting parameters from body
        access_token = request_header['Authorization']
        previous_password= request_body['oldPassword']
        proposed_password= request_body['newPassword']
        pool_name = request_body['teamName']
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
           app.log.error("Team does not exist , exception")
           return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
        
        # call to authorizer to check if caller is authorized
        authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "user")
        
        if(authorize['Status'] == ExitStatus.SUCCESS):
            changed_password = updateMemberPassword(access_token,previous_password,proposed_password)
            return changed_password
        else:
            return authorize
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}
    
        

def getUserRole(pool_id,username):
    try:
        response = client.admin_get_user(
            UserPoolId=pool_id,
            Username=username
            )
        role='user'
        user_dict= response['UserAttributes']
        for val in user_dict:
            if val['Name']=='custom:usertype':
                user_role=val['Value']
        app.log.debug("user role successfully: %s",str(role))
        return user_role
        
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to get user , exception : %s",str(e))
        return {'Status':ExitStatus.USER_NOT_FOUND,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to get user , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}     
    except Exception as e:
        app.log.error("Failed to get user , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}         
        
        
@app.route('/getUserRole',methods=['PUT'], cors=True)
def index():
    try:
        app.log.info("BEGIN: getUserRole API")   
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete User: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        # Getting parameters from body
        pool_name = request_body['teamName']
        username= request_body['userName']
        access_token = request_header['Authorization']
        
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
           app.log.error("Team does not exist , exception ")
           return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
           
        authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "user")
        if(authorize['Status'] == ExitStatus.SUCCESS):
            user_role = getUserRole(pool_id,username)
            return {"Status":str(user_role)}
        else:
            return authorize
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}
        

# updates the member profile information
def updateMemberProfile(access_token,user_attriutes):
    try:
        response = client.update_user_attributes(
            UserAttributes=user_attriutes,
            AccessToken=access_token
            )
        app.log.debug("user role successfully: %s",str(response))
        return {'Status':ExitStatus.SUCCESS,'Message':' Member updated successfully'}
   #     return response
    except client.exceptions.UserNotFoundException as e:
        app.log.error("Fail to update user profile  , exception : %s",str(e))
        return {'Status':ExitStatus.USER_NOT_FOUND,'Message':ExitMessage.ERR_MSG_USER_NOT_EXIST}
    except client.exceptions.NotAuthorizedException as e:
        app.log.error("Fail to update user profile , exception : %s",str(e))
        return {'Status':ExitStatus.ERR_USER_NOT_AUTHORIZED,'Message':ExitMessage.ERR_MSG_USER_NOT_AUTHORIZED}     
    except Exception as e:
        app.log.error("Failed to update user profile , exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)}    

#updateMember API
@app.route('/updateMember', methods=['POST'], cors=True)
def index():
    try:
        app.log.info("BEGIN: updateMember API")   
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
#        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
#            app.log.error("Fail to delete User: empty parameters")
#            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        if request_body['middleName'] == "" or None:
             request_body['middleName']= " "
        if request_body['country'] == "" or None:
             request_body['country']= " "
        if request_body['zoneInfo'] == "" or None:
             request_body['zoneInfo']= " "
        if request_body['company'] == "" or None:
             request_body['company']= " " 
        if request_body['jobTitle'] == "" or None:
             request_body['jobTitle']= " "
        if request_body['webPage'] == "" or None:
             request_body['webPage']= " "
        if request_body['aboutMe'] == "" or None:
             request_body['aboutMe']= " "          
        # Getting parameters from body
        access_token = request_header['Authorization']
        user_attriutes = [
            {
                'Name':'name',
                'Value': request_body['givenName']
            },
            {
                'Name':'middle_name',
                'Value': request_body['middleName']
            },
            {
                'Name':'family_name',
                'Value': request_body['familyName']
            },
            {
                'Name':'custom:country',
                'Value': request_body['country']
            },
            {
                'Name':'zoneinfo',
                'Value': request_body['zoneInfo']
            },
            {
                'Name':'custom:companyname',
                'Value': request_body['company']
            },
            {
                'Name':'custom:jobtitle',
                'Value': request_body['jobTitle']
            },
            {
                'Name':'custom:webPage',
                'Value': request_body['webPage']
            },
            {
                'Name':'custom:aboutme',
                'Value': request_body['aboutMe']
            }
            ]
        pool_name = request_body['teamName']    
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
           app.log.error("Team does not exist , exception")
           return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST}   
            
        authorize=chalicelib.utility.groupAuthorizer(pool_id, access_token, "user")
        if(authorize['Status'] == ExitStatus.SUCCESS):
            updated_profile = updateMemberProfile(access_token,user_attriutes)
            return updated_profile
        else:
            return authorize
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.ERR_KEY_ERROR,'Message':str(e)}
    except Exception as e:
        app.log.error("Failed to update user profile, exception : %s",str(e))
        return {'Status':ExitStatus.ERROR,'Message':str(e)} 
      


 
@app.route('/adminCount', methods=['POST'], cors=True) 
def index():
    app.log.info("BEGIN: count API")
    #Getting body
    request_body = app.current_request.json_body
    app.log.debug("REQUEST BODY= "+str(request_body))
        
        
    # Validation check to check for empty or null values
    if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
        app.log.error("Fail to delete User: empty parameters")
        return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        
            
    # Getting parameters from body
    pool_name= request_body['teamName']
        
        
    pool_id = chalicelib.utility.getUserPoolId(pool_name)
    if pool_id == "":
        app.log.error("Team does not exist , exception ")
        return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
    count = adminCount(pool_id)
    return count




@app.route('/encrypt', methods=['POST'], cors=True) 
def index():
    app.log.info("BEGIN: encrypt API")
    #Getting body
    request_body = app.current_request.json_body
    app.log.debug("REQUEST BODY= "+str(request_body))
    
    # Validation check to check for empty or null values
    if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
        app.log.error("Fail to delete User: empty parameters")
        return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
        
            
    # Getting parameters from body
    plain_text = request_body['plainText']
    
    chiper_text = chalicelib.utility.encryptCode(plain_text)
    app.log.info("decr:"+str(chiper_text))
    #return str(chiper_text)
    return json.dumps(chiper_text,default=json_beautify)

@app.route('/decryptCode', methods=['POST'], cors=True) 
def index():
    app.log.info("BEGIN: decrypt API")
    #Getting body
    request_body = app.current_request.json_body
    
    app.log.debug("REQUEST BODY= "+str(request_body))
    
    # Validation check to check for empty or null values
    if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
        app.log.error("Fail to delete User: empty parameters")
        return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
      
            
    # Getting parameters from body
    #cipher_text = request_body['CiphertextBlob']
    plain_text_list=[]
    encoded_list = request_body['encodedList']
    for encode_list in encoded_list:
        plain_text =chalicelib.utility.decryptCode(encode_list)
        plain_text_list.append(plain_text)
        
    return plain_text_list

@app.route('/checkMember', methods=['POST'], cors=True) 
def index():
    try:
        app.log.info("BEGIN: checkMember API")
        #Getting body
        request_body = app.current_request.json_body
        app.log.debug("REQUEST BODY= "+str(request_body))
        
        request_header=app.current_request.headers
        app.log.debug("REQUEST HEADER= "+str(request_header))
        
        # Validation check to check for empty or null values
        if(chalicelib.utility.isValid(request_body)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete User: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        if(chalicelib.utility.isValid(request_header)==ExitStatus.ERR_EMPTY_PARAMS):
            app.log.error("Fail to delete team: empty parameters")
            return {'status error':ExitStatus.ERR_EMPTY_PARAMS }
            
        # Getting parameters from body
        pool_name = request_body['teamName']
        username = request_body['email']
       
        pool_id = chalicelib.utility.getUserPoolId(pool_name)
        if pool_id == "":
           app.log.error("Team does not exist , exception")
           return 2
           #return {'Status':ExitStatus.ERR_TEAM_NOT_EXIST,'Message':ExitMessage.ERR_MSG_TEAM_NOT_EXIST} 
        
        get_member= findMember(pool_id,username)
        if get_member["Status"] == ExitStatus.SUCCESS:
            return 0
        else:
            return 1
    except KeyError as e:
        app.log.error('KeyError'+str(e))
        return {'Status':ExitStatus.KEY_ERROR,'Message':str(e)} 
'''

#util function
def json_beautify(inp):
    if isinstance(inp, datetime.datetime):
        return inp.__str__()