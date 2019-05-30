import pymongo
from datetime import datetime
from bson import ObjectId
import json
from bson import json_util
from datetime import datetime
import random

#aws documentdb
#master_user_name: inguodbuser
#master_password:inguodb123
#db_url = "mongodb://inguodbuser:inguodb123@docdb-2019-03-17-16-17-53.cluster-cygqxaldyl7z.us-east-2.docdb.amazonaws.com:27017/?ssl=true&ssl_ca_certs=rds-combined-ca-bundle.pem&replicaSet=rs0"
#wget https://s3.amazonaws.com/rds-downloads/rds-combined-ca-bundle.pem 


#db_url = "mongodb://localhost:27017/"
db_url = "mongodb://inguodbuser:inguodb123@docdb-2019-03-17-16-17-53.cluster-cygqxaldyl7z.us-east-2.docdb.amazonaws.com:27017/?ssl=false"
#db_url = "mongodb://inguodbuser:inguodb123@docdb-2019-03-17-16-17-53.cluster-cygqxaldyl7z.us-east-2.docdb.amazonaws.com:27017/?ssl=true&ssl_ca_certs=rds-combined#-ca-bundle.pem&replicaSet=rs0"
db_name = "inguo_db" # database name
collection = "comments"  # database table name

db_client = pymongo.MongoClient(db_url)
#db_client = pymongo.MongoClient('mongodb://inguodbuser:inguodb123@docdb-2019-03-17-16-17-53.cluster-cygqxaldyl7z.us-east-2.docdb.amazonaws.com', 
#						 27017, 
#						 ssl=True, 
#						 ssl_certfile='/path/to/client.pem',
#						 ssl_keyfile='/path/to/key.pem',
#						 ssl_ca_certs = './rds-combined-ca-bundle.pem')
#						 ssl_keyfile='./rds-combined-ca-bundle.pem')
db_con = db_client[db_name]
db_col = db_con[collection]

def getUniqueId():
	return datetime.now().strftime('%Y%m%d%H%M%S')+ str(random.randint(1001,1099))

def getAllPostData(team_name,project_name):
	list_of_post = []
	cursor = db_col.find({"team_name":team_name, "project_name":project_name})
	for dict_record in cursor:
		list_of_post.append(dict_record)
	return list_of_post  #to do json.dumps(list_of_post)
	

def addPost(team_name,project_name,post_text,posted_by):
	date = datetime.utcnow()
	posted_date = date.strftime('%Y.%m.%d.%H.%M.%S')
	comments = []
	_id = str(getUniqueId())
	post_dict = {"_id":_id,"team_name":team_name,"project_name":project_name,"post_text":post_text,\
		"posted_by":posted_by,"posted_date":posted_date,"comments":comments}
        db_col.insert_one(post_dict)
        return "success"
    
def addCommentToPost(post_id,comment_text,commented_by,inreplyto):
	date = datetime.utcnow()
	commented_date = date.strftime('%Y.%m.%d.%H.%M.%S')
        comment_dict = {"comment_id":str(getUniqueId()),"comment_text":comment_text,"commented_by":commented_by, \
		"commented_date":commented_date,"inreplyto":inreplyto}	
	db_col.update_one({"_id":post_id},{'$push': {'comments': comment_dict}})
