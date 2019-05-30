class ExitStatus:

      #Below are the error codes for generic issues
      SUCCESS = 200
      ERROR = 0
      ERR_EMPTY_PARAMS = 2
      
      #Team Related (1001 - 1010)
      ERR_TEAM_NOT_EXIST = 1001
      ERR_TEAM_ALREADY_EXIST = 1002
      ERR_POLICY_LENGHT_EXCEEDED = 1003
      ERR_RESOURCE_CONFLICIT = 1004
      ERR_SERVICE_EXCEPTION = 1005
      
     #User Related (1011 - 1030)
      ERR_USER_NOT_EXIST = 1011
      ERR_USER_ALREADY_EXIST = 1013
      ERR_USER_NOT_AUTHORIZED = 1012
      ERR_INVALID_OLD_PASSWORD = 1014
      ERR_CODE_DELIVERY_FAILURE = 1016
      ERR_MEMBER_NOT_CONFIRMED = 1017
      ERR_CODE_MISMATCH = 1018
      ERR_CODE_EXPIRED = 1019
      ERR_LIMIT_EXCEEDED=1020
      ERR_ONLY_ONE_ADMIN=1021
      
      #Project Related (1040 - 1070)
      ERR_PROJECT_ALREADY_EXIST = 1040
      ERR_PROJECT_NOT_EXIST = 1041
      
      
      ERR_INVALID_PARAMS = 1042
      ERR_RES_NOT_FOUND = 1043     
      ERR_KEY_ERROR=1015

class ExitMessage:
      
      MSG_SUCCESS = "Operation completed successfully."
      ERR_MSG_INVALID_PARAMS="Invalid parameters"
      ERR_MSG_RES_NOT_FOUND="Required resource not found"
      
      ERR_MSG_TEAM_NOT_EXIST = "Team not exist."
      ERR_MSG_TEAM_ALREADY_EXIST = "Team already exist."
      ERR_MSG_POLICY_LENGHT_EXCEEDED ="Policy lenght exceeded adding lambda permission"
      ERR_MSG_RESOURCE_CONFLICIT = "The resource already exists while adding lambda permission." 
      ERR_MSG_SERVICE_EXCEPTION = "lambda permission: Internal error."
      
      ERR_MSG_USER_NOT_EXIST = "Member not exist."
      ERR_MSG_USER_ALREADY_EXIST = "Member already exist."
      ERR_MSG_USER_NOT_AUTHORIZED = "Member is not authorized to perform operation."
      ERR_MSG_INVALID_OLD_PASSWORD = "Old password is incorrect."
      ERR_MSG_CODE_DELIVERY_FAILURE = "Failed to delivered confirmation code"
      ERR_MSG_MEMBER_NOT_CONFIRMED = "Member is not confirmed"
      ERR_MSG_CODE_MISMATCH = "Confirmation code mismath"
      ERR_MSG_CODE_EXPIRED = "Confirmation code expired"
      ERR_MSG_LIMIT_EXCEEDED = "Attempt limit exceeded"
      ERR_MSG_ONLY_ONE_ADMIN ="Only one admin in team,please add one more"
      
      ERR_MSG_PROJECT_ALREADY_EXIST = "Project is already exist."
      ERR_MSG_PROJECT_NOT_EXIST = "Project not exist."
      
      