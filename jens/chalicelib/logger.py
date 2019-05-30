import logging
import os
import re
#from datetime import datetime, timezone

# Class Name: Logger
# Description: It is a class that provide logger functionality.
#                This class contains class method "initiLogger"
#               that reads lambda environment variable LOG_LEVEL
#               and initialize logger.
# Input: None
# Output


class Logger:
    logger = None

    # Name: initLogger
    # Description: It is a class method that reads lambda environment
    #              variable LOG_LEVEL and initialize logger. Call
    #              this function in the begining of every micro service
    #              code.
    # Input: None
    # Output: logger variable
    @classmethod
    def initLogger(cls):
        if cls.logger is None:
            cls.logger = logging.getLogger()
            if os.environ['LOG_LEVEL'] == "INFO":
                cls.logger.setLevel(logging.INFO)
            elif os.environ['LOG_LEVEL'] == "DEBUG":
                cls.logger.setLevel(logging.DEBUG)
            elif os.environ['LOG_LEVEL'] == "ERROR":
                cls.logger.setLevel(logging.ERROR)
            elif os.environ['LOG_LEVEL'] == "WARN":
                cls.logger.setLevel(logging.WARNING)
        return cls.logger

'''
class Utility:
    @classmethod
    def giveRFC3339Time(cls):
        local_time = datetime.now(timezone.utc).astimezone()
        isoTime = local_time.isoformat()
        return re.sub(r'\.[0-9]+', '', isoTime)

    @classmethod
    def eventTime(cls):
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S" + 'Z')
'''