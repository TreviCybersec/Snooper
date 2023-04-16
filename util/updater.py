
import subprocess

import os

from util.utils import Utils
from util.slogger import Slogger

from termcolor import colored

import webtech

class Updater(object):

    def __init__(self, logger):
        self.logger = logger

    def update(self, package_name):
        
        utils_module = Utils()
        self.logger.print_title("UPDATING PACKAGE '" + package_name + "'")
        
        if utils_module.check_network_connectivity():
            
            # Webtech needs to update the wappalyzer files
            if package_name == "webtech":
                webtech.database.update_database(force=True)
            
            else:
                bash_command = "sudo apt install -y --only-upgrade {}".format(package_name)
                process_update = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)

                while process_update.poll() is None:
                
                    line = process_update.stdout.readline()
                    line = line.decode("utf-8").rstrip()
                    if line:
                        self.logger.info(text=line, label=False)
                
                output, error = process_update.communicate()
            
        else:
            self.logger.error("Network connection not available. Unable to update package...")
            self.logger.info("Consider running apt manually")
            
            
