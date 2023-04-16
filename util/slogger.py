

import pyfiglet

from pathlib import Path

from termcolor import colored


class Slogger(object):

    def print_title(self, title: str):
            
        print(colored("\n\n========================================================================", "blue", attrs=['bold']))
        print(colored(title, "blue", attrs=['bold']))
        print(colored("========================================================================\n", "blue", attrs=['bold']))

    def print_logo(self):        
        pyftitle = pyfiglet.Figlet(font="epic", width=80)
        print("\n\n" + colored(pyftitle.renderText('snooper'), "red", attrs=['bold']))
        print("\t\t\t{:>12}".format(colored("authors: Simone Scalco and David Tancredi", "red")))
        print("\t\t\t{:>12}".format(colored("Trevigroup s.r.l.\n\n", "red")))
        
    def color_text(self, text: str, color: str):
        return colored(text, color)
        
    def bold_text(self, text: str):
        return colored(text, attrs=['bold'])
        
    def info(self, text="", is_bold=False, label=True):
    
        if label:
            if is_bold:
                print(self.color_text("[INF]", "blue") + " " + self.bold_text(text))
            else:
                print(self.color_text("[INF]", "blue") + " " + text)
        else:
            print(text)
    
    def info_indented(self, text="", indent=1):
        str_indented = ""
        for i in range(0, indent):
            str_indented += "\t"
        
        print("{}| {}".format(str_indented, text))
    
    def error(self, text="", is_bold=False):
        print(self.color_text("[ERR]", "red") + " " + text)
    
    def warning(self, text="", is_bold=False):
        print(self.color_text("[WRN]", "yellow") + " " + text)
    
    def info_params(self, text="", param=""):
        
        if param:
            print(self.color_text("[INF]", "blue") + " " + text + " " + self.bold_colored_text(str(param), "green"))
        else:
            print(self.color_text("[INF]", "blue") + " " + text + " " + self.bold_colored_text(str(param), "red"))
        
    def info_sub(self, text="", sub=""):
        print(self.color_text("[INF:", "blue") + self.bold_colored_text(sub, "blue") + self.color_text("]", "blue") + " " + text)
    
    def bold_colored_text(self, text: str, color: str):
        return colored(text, color, attrs=['bold'])
    
    def highlight_text(self, text: str):
        return colored(text, "white", "on_light_blue")
        
        
