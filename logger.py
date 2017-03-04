import logging
import random
logger = None
colors = {
          'info': '\033[1;92m',
          'debug': '\033[0;94m',
          'warning':'\033[1;93m',
          'error':'\033[1;31m',
          'critical':'\033[1;31m'
          }

class_colors = [24,34,44,54,64,74,84,94,104,114,124,134,144,154,164,174,184,194,204,214,224,234,244,254]


no_color = '\033[0m'

def getLogger(class_name, level):
    '''
    This function will create a logger and returns it. The logger object is 
    logging to stdout considering the given logging level, and also logs into
    a file with loglevel DEBUG to print out everything
    class_name String - the class name that asks for a logger object
    level String - the desired logging level (DEBUG, INFO, WARNING, ERROR, 
    CRITICAL
    timestamp - time stamp for the name of the log file
    path - the path the log file should be saved
    '''


    #we randomize color list each time this function is called to assign random colors to different classes
    random.shuffle(class_colors)

    logger = logging.getLogger(class_name)

    #if logger already has handlers, it means that it is already configured,
    #so we just pass back the reference
    if logger.handlers:
        return logger


    c_name = "\033[38;5;{}m{}{}".format(class_colors.pop(), class_name, no_color)
    logger.__setattr__("name", c_name)
    # timestamp = df.getDateFormat(timestamp)
    #
    # #remove log/ from the path, and check the parent directory's existence
    # path_parent_dir = path[:-4]
    #
    # if not (os.path.isdir(path_parent_dir)):
    #         print("Path to create log/ directory (%s) does not exist!" %
    #                       path_parent_dir)
    #         print("EXITING...")
    #         exit(-1)
    #
    #
    # #create the log directory
    # if not os.path.exists(path):
    #     os.makedirs(path)
    #
    #
    #  # create file handler which logs even debug messages
    # fh = logging.FileHandler(path + '/log_' + timestamp + ".log")
    # fh.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    ch = logging.StreamHandler()
    
    
    level = level.upper()
    if level == "DEBUG":
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)
    elif level == "INFO":
        logger.setLevel(logging.INFO)
        ch.setLevel(logging.INFO)
    elif level == "WARNING":
        logger.setLevel(logging.WARNING)
        ch.setLevel(logging.WARNING)
    elif level == "ERROR":
        logger.setLevel(logging.ERROR)
        ch.setLevel(logging.ERROR)
    elif level == "CRITICAL":
        logger.setLevel(logging.CRITICAL)
        ch.setLevel(logging.CRITICAL)
    else:
        print("Log level was not set properly...set to default DEBUG")
        logger.setLevel(logging.DEBUG)
    
            
        
    
    logging.addLevelName( logging.INFO, str("%s%s%s" % 
                                       (colors['info'], 
                                        logging.getLevelName(logging.INFO),
                                        no_color)))
    logging.addLevelName( logging.DEBUG, str("%s%s%s" % 
                                       (colors['debug'], 
                                        logging.getLevelName(logging.DEBUG),
                                        no_color)))
    logging.addLevelName( logging.WARNING, str("%s%s%s" % 
                                       (colors['warning'], 
                                        logging.getLevelName(logging.WARNING),
                                        no_color)))
    logging.addLevelName( logging.ERROR, str("%s%s%s" % 
                                       (colors['error'], 
                                        logging.getLevelName(logging.ERROR),
                                        no_color)))
    logging.addLevelName( logging.CRITICAL, str("%s%s%s" % 
                                       (colors['critical'], 
                                        logging.getLevelName(logging.CRITICAL),
                                        no_color)))
    
#     logging.addLevelName( logging.ERROR, "\033[1;41m%s\033[1;0m" % logging.getLevelName(logging.ERROR))
   
    # create formatter and add it to the handlers
    formatter = logging.Formatter('[%(name)s] - %(levelname)s')
    ch.setFormatter(formatter)
    # fh.setFormatter(formatter)

    # add the handlers to logger
    logger.addHandler(ch)
    # logger.addHandler(fh)

    return logger