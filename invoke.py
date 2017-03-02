from subprocess import (PIPE, Popen)


def invoke(**params):
    '''
 This helper function uses subprocess lib to execute system command.
 This could be helpful in case of errors, since reading the return value
 passed by this function enables to write out system command errors into the
 log file.

 :param command: the system command itself
 :param logger: logger object from the calling class to make it possible to log
 :param email_adapter: the main instance of email adapter to make this function able to send
 the final log message if an error occurred.
 :return: if no error: list of [stdout, exit code, stderr], otherwise it exits the application and prints the exit_code
 and the corresponding error
 '''

    command = params.get('command', None)


    process = Popen(command, stdout=PIPE, stderr=PIPE, shell=True)
    stdout, stderr = process.communicate()
    exit_code = process.wait()

    # create a list of the elements
    retList = [stdout, exit_code, stderr]
    # this will look like
    # [('stdout of command','stderr_if_happened'), exit_code]
    # for instance:
    # NO ERROR
    # invoke("cat /proc/meminfo|grep -i hugePages_free")
    # [('HugePages_Free:        0\n', ''), 0]
    #
    # ERROR:
    # invoke("cat /proc/meminfod|grep -i hugePages_free")
    # [('', 'cat: /proc/meminfod: No such file or directory\n'), 1]

    if (retList[1] != 0):

       print("Error during executing command: %s" % command)
       print("Error: %s" % str(retList[2]))
       print("Exit_code: %s" % str(retList[1]))

       exit(-1)

    return retList

