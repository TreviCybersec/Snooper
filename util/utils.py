
import socket
import pyfiglet
import base64

from pathlib import Path
from termcolor import colored
from util.slogger import Slogger

class Utils(object):

    def __init__(self, logger):
        self.logger = logger

    def check_network_connectivity(self, host="8.8.8.8", port=53, timeout=3):
        """
        Host: 8.8.8.8 (google-public-dns-a.google.com)
        OpenPort: 53/tcp
        Service: domain (DNS/TCP)
        """
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
            
        except socket.error as ex:
            return False

    def buf_count_newlines_gen(fname):
        def _make_gen(reader):
            while True:
                b = reader(2 ** 16)
                if not b: break
                yield b

        with open(fname, "rb") as f:
            count = sum(buf.count(b"\n") for buf in _make_gen(f.raw.read))
        return count
    
    @staticmethod
    def create_dir(directory: str):
        Path(directory).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def remove_file(file_path: str):
        file_path_handle = Path(file_path)
        file_path_handle.unlink(missing_ok=True)
        
    @staticmethod
    def remove_dir(directory: str):
        dir_path = Path(directory)
        if dir_path.exists() and dir_path.is_dir():
            shutil.rmtree(directory, ignore_errors=True)
            
    @staticmethod
    def check_if_file_exists(path_to_file: str):
        path = Path(path_to_file)
        if path.exists():
            return True
        
        return False
    
    def is_base64(self, sb):
    
        try:
            if isinstance(sb, str):
                # If there's any unicode here, an exception will be thrown and the function will return false
               sb_bytes = bytes(sb, 'ascii')
            elif isinstance(sb, bytes):
               sb_bytes = sb
            else:
               raise ValueError("Argument must be string or bytes")
            
            return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
        
        except Exception as ex:
            return False
            
    def get_inf_label(self, text=""):
        
        if text == "":
            return self.logger.color_text("[INF]", "blue") + " "
        else:
            return self.logger.color_text("[INF:", "blue") + self.logger.bold_colored_text(text, "blue") + self.logger.color_text("]", "blue") + " "
        
    def bold_text(self, text: str):
        return colored(text, attrs=['bold'])
        
        
