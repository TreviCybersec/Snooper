import sys
import argparse

import os
import subprocess
import re

import base64

import bisect

import json

import validators

import signal
import atexit

import webtech

from pathlib import Path

from tqdm import tqdm
from pathlib import Path
from time import sleep

from modules.dnsdumpster import DNSDumpster
from util.updater import Updater
from util.utils import Utils
from util.slogger import Slogger

IN_FILE_JSON_KNOWN_PORTS = "ports.json"

OUT_FILE_SSLSCAN_PLAIN = "sslscan_plain.txt"
OUT_FILE_SSLSCAN_COLOR = "sslscan_color.txt"
OUT_FILE_ASSETFINDER = "subs_assetf.txt"
OUT_FILE_AMASS = "subs_amass.txt"
OUT_FILE_SUBFINDER = "subs_subfinder.txt"
OUT_FILE_ALL_SUBS = "subs_all.txt"
OUT_FILE_ALL_SUBS_UNIQUE = "subs_all_unique.txt"
OUT_FILE_ALL_SUBS_UNIQUE_HTTPX = "subs_all_unique_httpx.txt"

OUT_FILE_NAABU = "naabu.txt"
OUT_FILE_LOGSENSOR_DEFAULT = "logPanels.txt"
OUT_FILE_LOGSENSOR = "logsensor_login_panels.txt"
OUT_FILE_WEB_SPIDER = "blackwidow_dynamic_unique.txt"
OUT_FILE_CLOUD_ENUM = "cloud_enum.txt"

OUT_FILE_NUCLEI_INFO = "nuclei_info.txt"
OUT_FILE_NUCLEI_COLOR = "nuclei_out_color.txt"
OUT_FILE_NUCLEI_PLAIN = "nuclei_out_plain.txt"


def force_sudo():
    res_sudo = 0
    if os.geteuid() != 0:
        msg = "[sudo] password for %u:"

        try:
            res_sudo = subprocess.check_call("sudo -v -p '%s'" % msg, shell=True)
        except subprocess.CalledProcessError as ex:
            logger.info("You need to run me with sudo!")
            exit()

    return res_sudo


def signal_handler(sig, frame):
    # print("\nSignal: " + str(sig) + ", " + str(frame))

    if sig == 2:
        print('\nCtrl+C event detected')
    elif sig == 20:
        print('\nCtrl+Z event detected')

    while True:
        user_choice = input("Do you really want to terminate the program? (y/n): ")

        if user_choice in ['y', 'Y']:
            # Add code for stopping processes
            sys.exit(0)
        else:
            return


def exit_func():
    print("Testing")


if __name__ == "__main__":

    # atexit.register(exit_func)
    signal.signal(signal.SIGINT, signal_handler)  # CTRL+C signal
    signal.signal(signal.SIGTSTP, signal_handler)  # CTRL+Z signal
    # print('Press Ctrl+C or Ctrl+Z')
    # signal.pause()

    force_sudo()

    parser = argparse.ArgumentParser(
        prog="Snooper",
        description="Attack surface analyser",
        # add_help=False,
        epilog="version: 0.2-alpha")

    parser.add_argument(
        '-t',
        '--target',
        required=True,
        type=str,
        help='Specify the target domain'
    )

    parser.add_argument(
        '-aj',
        '--arjun',
        required=False,
        default=False,
        action='store_true',
        help='Run Arjun module'
    )

    parser.add_argument(
        '-ce',
        '--cloud_enum',
        required=False,
        default=False,
        action='store_true',
        help='Run cloud-enum module (for cloud resource enumeration)'
    )

    parser.add_argument(
        '-dns',
        '--dns',
        required=False,
        # default='domain',
        # const='domain',
        # nargs='?',
        choices=['all', 'domain'],
        help='WIP Use dnsdumpster APIs for every subdomain (all) or just the domain (domain)'
    )

    parser.add_argument(
        '-o',
        '--osint',
        required=False,
        default='all',
        const='all',
        nargs='?',
        choices=['all', 'email'],
        help='WIP Use "_______" APIs to perform OSINT activity'
    )

    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='%(prog)s 0.2-alpha',
        help="Show the program's version number and exit"
    )

    parser.add_argument(
        '-u',
        '--update',
        action='store_true',
        help="WIP update all the tools used by snooper"
    )

    parser.add_argument(
        '-f',
        '--fast',
        action='store_true',
        help="Run only subdomain bruteforcing and vulnerability scanning"
    )
    """                 
    parser.add_argument(
        '-h',
        '--help',
        action='help',
        default=argparse.SUPPRESS,
        help='Show this help message and exit.'
    )
    """

    # Parse arguments
    args = parser.parse_args()
    input_domain = args.target
    enable_module_arjun = args.arjun
    enable_module_cloud_enum = args.cloud_enum
    enable_module_dnsdumpster = args.dns
    enable_fast_mode = args.fast

    # Clear the interpreter console
    clear = lambda: os.system('clear')
    clear()

    # Init the main utility modules
    logger = Slogger()
    logger.print_logo()
    utils_module = Utils(logger)

    # Updating only APT packages
    if input_domain == "update":
        logger.info("Checking for network connectivity")
        if utils_module.check_network_connectivity():

            updater_module = Updater(logger)
            updater_module.update("sslscan")
            updater_module.update("assetfinder")
            updater_module.update("amass")
            updater_module.update("naabu")
            updater_module.update("cloud-enum")
            updater_module.update("arjun")
            # updater_module.update("python3-httpx")
            updater_module.update("httpx-toolkit")
            updater_module.update("webtech")

        else:
            logger.error("Network connection not available, unable to update packages...")

        logger.print_title("UPDATE PROCESS COMPLETED")
        sys.exit(0)

    # Showing selected configuration to the user
    logger.info(text="CURRENT CONFIGURATION:", is_bold=True)
    logger.info_params(text="Arjun:", param=enable_module_arjun)
    logger.info_params(text="Cloud enum:", param=enable_module_cloud_enum)
    logger.info_params(text="DNS dump:", param=enable_module_dnsdumpster)

    # Check for valid domain
    print("")
    if validators.domain(input_domain):
        logger.info("Valid domain inserted: '{}'".format(input_domain))

    else:
        logger.error("The inserted domain ({}) is not valid".format(input_domain))
        logger.error("Check the domain and try again")
        sys.exit(1)

    input_domain_name = input_domain[0:input_domain.rfind(".")]
    logger.info("Parsed input name: {}".format(input_domain_name))

    """
    if not utils_module.check_network_connectivity():
        logger.error("Network connection not available")
        sys.exit(1)
    """

    # Set the loot directory for the input domain
    OUT_MAIN_DIR = "output/"
    OUT_LOCAL_LOOT = OUT_MAIN_DIR + "{}/".format(input_domain)
    OUT_LOCAL_LOOT_SUBS = OUT_LOCAL_LOOT + "subs/"
    OUT_LOCAL_LOOT_DNSDUMPSTER = OUT_LOCAL_LOOT + "dnsdumpster/"
    OUT_LOCAL_LOOT_SSLSCAN = OUT_LOCAL_LOOT + "sslscan/"
    OUT_LOCAL_LOOT_NUCLEI = OUT_LOCAL_LOOT + "nuclei/"

    # Creating the directories to store the results
    utils_module.create_dir(OUT_LOCAL_LOOT)
    utils_module.create_dir(OUT_LOCAL_LOOT_SUBS)
    utils_module.create_dir(OUT_LOCAL_LOOT_DNSDUMPSTER)
    utils_module.create_dir(OUT_LOCAL_LOOT_SSLSCAN)
    utils_module.create_dir(OUT_LOCAL_LOOT_NUCLEI)

    #################################################################################
    ##### TODO: CHANGE THE OWNERSHIP OF THE OUTPUT FOLDER
    #################################################################################

    # chown -R someuser:somegroup /your/folder/here/*

    #################################################################################
    ##### CLOUD-ENUM
    #################################################################################

    if enable_module_cloud_enum:
        logger.info("Running cloud enumeration tools in the background...")

        # Executing cloud enum process
        bash_command = ("cloud_enum -k {} -k {} -l {}").format(input_domain, input_domain_name,
                                                               OUT_LOCAL_LOOT + OUT_FILE_CLOUD_ENUM)
        process_cloud = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, bufsize=50)

    #################################################################################
    ##### SCANNING SSL/TLS PROTOCOLS
    #################################################################################

    if not enable_fast_mode:
        logger.print_title("SCANNING SSL/TLS PROTOCOLS")

        # Execute sslscan process
        bash_command = "sslscan {}".format(input_domain)
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   encoding="utf-8")
        output, error = process.communicate()
        output_plain = re.sub(r'\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))', '', output)

        # Write output files (plain and color to the target directory)
        sslscan_out_file_plain = open(OUT_LOCAL_LOOT_SSLSCAN + OUT_FILE_SSLSCAN_PLAIN, "w", encoding="utf-8")
        sslscan_out_file_plain.write(output_plain)
        sslscan_out_file_plain.close()
        sslscan_out_file_color = open(OUT_LOCAL_LOOT_SSLSCAN + OUT_FILE_SSLSCAN_COLOR, "w", encoding="utf-8")
        sslscan_out_file_color.write(output)
        sslscan_out_file_color.close()

        logger.info(text=output, label=False)

    #################################################################################
    ##### RUNNING ASSETFINDER
    #################################################################################

    logger.print_title("SUBDOMAIN BRUTEFORCING")
    logger.info("Running step 1...")
    assetf_out_file = open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ASSETFINDER, "w")

    # Executing assetfinder process
    bash_command = "assetfinder -subs-only {}".format(input_domain)
    process = subprocess.Popen(bash_command.split(), stdout=assetf_out_file)
    output, error = process.communicate()

    assetf_out_file.close()

    # Check the file size (if size is 0 bytes it means assetfinder couldn't find any subdomain)
    if os.stat(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ASSETFINDER).st_size == 0:
        logger.warning("No subdomain found for {}".format(input_domain))

    #################################################################################
    ##### RUNNING AMASS
    #################################################################################

    logger.info("Running step 2...")
    amass_out_file = open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_AMASS, "w")

    # Executing amass process
    bash_command = "amass enum -d {} -brute".format(input_domain)
    process = subprocess.Popen(bash_command.split(), stdout=amass_out_file, stderr=subprocess.DEVNULL)
    output, error = process.communicate()

    # Check the file size (if size is 0 bytes it means amass couldn't find any subdomain)
    if os.stat(OUT_LOCAL_LOOT_SUBS + OUT_FILE_AMASS).st_size == 0:
        logger.warning("No subdomain found for {}".format(input_domain))

    #################################################################################
    ##### RUNNING SUBFINDER
    #################################################################################

    logger.info("Running step 3...")
    subf_out_file = open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_SUBFINDER, "w")

    # Executing subfinder process
    bash_command = "sudo subfinder -d {}".format(input_domain)
    process = subprocess.Popen(bash_command.split(), stdout=subf_out_file, stderr=subprocess.DEVNULL)
    output, error = process.communicate()

    subf_out_file.close()

    # Check the file size (if size is 0 bytes it means subfinder couldn't find any subdomain)
    if os.stat(OUT_LOCAL_LOOT_SUBS + OUT_FILE_SUBFINDER).st_size == 0:
        logger.warning("No subdomain found for {}".format(input_domain))

    #################################################################################
    ##### MERGING SUBS
    #################################################################################

    # Merge files of subs
    with open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS, "w") as subs:
        assetf_out_file = open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ASSETFINDER, "r")
        amass_out_file = open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_AMASS, "r")
        subf_out_file = open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_SUBFINDER, "r")

        subs.writelines([l for l in assetf_out_file.readlines()])
        subs.writelines([l for l in amass_out_file.readlines()])
        subs.writelines([l for l in subf_out_file.readlines()])

        assetf_out_file.close()
        amass_out_file.close()
        subf_out_file.close()

    #################################################################################
    ##### SORTING SUBS
    #################################################################################

    # Retrieve only unique subs from the three files produced in the previous steps
    bash_command = ("sort -u {} -o {}").format(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS,
                                               OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE)
    process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    utils_module.remove_file(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ASSETFINDER)
    utils_module.remove_file(OUT_LOCAL_LOOT_SUBS + OUT_FILE_AMASS)
    utils_module.remove_file(OUT_LOCAL_LOOT_SUBS + OUT_FILE_SUBFINDER)
    utils_module.remove_file(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS)

    # Retrieving the subdomains from the file
    subs_count = 0
    subs_list = []
    with open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE, "r", encoding="utf-8") as subs_unique_file:
        # print(os.stat("subs_all_unique.txt").st_size)
        # subs_list = [l for l in subs_unique_file.readlines()]

        for line in subs_unique_file.readlines():
            subs_count += 1
            subs_list.append(line.strip())

    logger.info("Unique subdomains found: {}".format(subs_count))

    #################################################################################
    ##### CHECKING A/MX/DNS RECORDS
    #################################################################################

    if enable_module_dnsdumpster:
        logger.print_title("ENUMERATING DNS RECORDS (A, MX, SOA, NS, AAAA, SPF and TXT)")
        logger.info("Target domain: {}".format(input_domain))

        try:
            res = DNSDumpster({'verbose': False}).search(input_domain)

            try:
                with open(OUT_LOCAL_LOOT_DNSDUMPSTER + input_domain + ".png", "wb") as dnsmap_file:
                    if utils_module.is_base64(res['image_data']):
                        logger.info_indented("DNS map file found!")
                        dnsmap_file.write(base64.decodebytes(res['image_data']))

            except Exception as ex:
                logger.info_indented("No DNS map found for: {}".format(input_domain))
                utils_module.remove_file(OUT_LOCAL_LOOT_DNSDUMPSTER + input_domain + ".png")

            try:
                with open(OUT_LOCAL_LOOT_DNSDUMPSTER + input_domain + ".xlsx", "wb") as dnsxlsx_file:
                    if utils_module.is_base64(res['xls_data']):
                        logger.info_indented("XLS mappings file found!")
                        dnsxlsx_file.write(base64.decodebytes(res['xls_data']))

            except Exception as ex:
                logger.info_indented("No XLS mappings file found for: {}".format(input_domain))
                utils_module.remove_file(OUT_LOCAL_LOOT_DNSDUMPSTER + input_domain + ".xlsx")

            # In this case it will crawl dnsdumpster for the domain and all subdomains found
            if enable_module_dnsdumpster == "all":
                for sub in subs_list:
                    if sub != input_domain:

                        logger.info("Target subdomain: {}".format(sub))
                        res = DNSDumpster({'verbose': False}).search(sub)

                        try:
                            with open(OUT_LOCAL_LOOT_DNSDUMPSTER + sub + ".png", "wb") as dnsmap_file:

                                if utils_module.is_base64(res['image_data']):
                                    logger.info_indented("DNS map file found!")
                                    dnsmap_file.write(base64.decodebytes(res['image_data']))

                        except Exception as ex:
                            logger.info_indented("No DNS map found for: {}".format(sub))
                            utils_module.remove_file(OUT_LOCAL_LOOT_DNSDUMPSTER + sub + ".png")

                        try:
                            with open(OUT_LOCAL_LOOT_DNSDUMPSTER + sub + ".xlsx", "wb") as dnsxlsx_file:

                                if utils_module.is_base64(res['xls_data']):
                                    logger.info_indented("XLS mappings file found!")
                                    dnsxlsx_file.write(base64.decodebytes(res['xls_data']))

                        except Exception as ex:
                            logger.info_indented("No XLS mappings file found for: {}".format(sub))
                            utils_module.remove_file(OUT_LOCAL_LOOT_DNSDUMPSTER + sub + ".xlsx")

        except:
            logger.error("Unable to retrieve DNS records")

    #################################################################################
    ##### CHECKING ACTIVE URLS
    #################################################################################

    logger.print_title("CHECKING ACTIVE URLS")

    # Executing httpx process
    bash_command = "httpx-toolkit -l {} -o {}".format(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE,
                                                      OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE_HTTPX)
    process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()

    subs_httpx_list = []
    count_httpx_found = 0
    single_url = ""
    # Separating the output chars in lines
    for char in output.decode("utf-8"):
        if char != "\n":
            single_url += char
        if char == "\n":
            count_httpx_found += 1
            subs_httpx_list.append(single_url)
            single_url = ""

    logger.info("URLs found: {}".format(count_httpx_found))
    for url in subs_httpx_list:
        logger.info_indented(url)

    #################################################################################
    ##### PORT SCANNING
    #################################################################################

    if not enable_fast_mode:
        logger.print_title("PORT SCANNING")

        # Executing naabu process
        bash_command = "sudo naabu -l {} -tp 100 -o {} -json".format(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE,
                                                                     OUT_LOCAL_LOOT + OUT_FILE_NAABU)
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()

        enable_port_mappings = True
        json_ports = ""
        # Mapping all the known ports
        with open("modules/" + IN_FILE_JSON_KNOWN_PORTS, "r") as ports_in_file:
            lines = ports_in_file.readlines()
            json_to_parse = ""
            for line in lines:
                json_to_parse += line

            # Loading json of known ports
            try:
                json_ports = json.loads(json_to_parse)

            except Exception as ex:
                logger.warning("Unable to load the file containing port mappings")
                enable_port_mappings = False

        # Reading naabu output file and map the ports to known services that might be running behind them
        dict_naabu = dict()
        with open(OUT_LOCAL_LOOT + OUT_FILE_NAABU, "r", encoding="utf-8") as naabu_out_file:
            for line in naabu_out_file.readlines():
                data = json.loads(line)

                sub = data["host"]
                ip_addr = data["ip"]
                port = data["port"]
                key = sub + " : " + ip_addr

                if key not in dict_naabu.keys():
                    dict_naabu[key] = []
                # Sorted insert
                bisect.insort(dict_naabu[key], int(port))

        # Printing the results to stdout
        for key in dict_naabu.keys():
            print("\n" + utils_module.get_inf_label() + "Ports found for host " + logger.bold_text(
                key) + " (total: " + str(len(dict_naabu[key])) + ")")

            port_name = "Unknown"
            port_description = "Unknown"

            for port in dict_naabu[key]:

                if enable_port_mappings:
                    try:
                        for mapping in json_ports.keys():
                            if mapping.startswith(str(port) + "/"):
                                if "name" in json_ports[mapping]:
                                    port_name = json_ports[mapping]["name"]
                                if "description" in json_ports[mapping]:
                                    port_description = json_ports[mapping]["description"]

                    except Exception as ex:
                        port_name = "Unknown"
                        port_description = "Unknown"

                print("\t" + utils_module.bold_text("| " + str(port)) + "\t--> " + port_name + ": " + port_description)

    #################################################################################
    ##### SEARCHING FOR LOGIN PANELS
    #################################################################################

    if not enable_fast_mode:
        logger.print_title("SEARCHING FOR LOGIN PANELS")

        # Searching for login panels in all active URLs
        login_panels_list = []
        for sub in subs_httpx_list:

            logger.info("Target URL: {}".format(logger.bold_text(sub)))

            # Executing logsensor process
            bash_command = "logsensor -u " + sub + " -l"
            process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE)

            while process.poll() is None:
                line = process.stdout.readline()
                line = line.decode("utf-8").strip()
                if line:
                    if line.startswith("[+] Login panel found"):
                        sanitized_line = line.replace("[+] Login panel found !", "Login panel:")
                        logger.info_indented(sanitized_line)
                    #elif line.startswith("[+] There are no Login Panels"):
                    #    print("\tNo login panels found")

            print("")
            output, error = process.communicate()

            # Read the default output file of logsensor
            if os.path.isfile(OUT_FILE_LOGSENSOR_DEFAULT):
                with open(OUT_FILE_LOGSENSOR_DEFAULT, "r", encoding="utf-8") as log_panels_file:
                    for line in log_panels_file.readlines():
                        login_panels_list.append(line)

        # Writing new output file
        # It would have been easier to just move the default output file,
        # but in this case we can also sanitize the output if we need to
        with open(OUT_LOCAL_LOOT + OUT_FILE_LOGSENSOR, "w", encoding="utf-8") as log_panels_out_file:
            for entry in login_panels_list:
                log_panels_out_file.write(entry)

        # Executing rm process (removing the output file from the local directory)
        # Executing directly instead of opening a new subprocess
        bash_command = "rm {} 2>/dev/null".format(OUT_FILE_LOGSENSOR_DEFAULT)
        process = subprocess.call(bash_command, shell=True, stdout=subprocess.PIPE, bufsize=2)

    #################################################################################
    ##### RUNNING WEBTECH
    #################################################################################

    if not enable_fast_mode:
        logger.print_title("IDENTIFYING WEB TECHNOLOGIES")

        # Runnning python webtech for all elements of the list retrieved by httpx
        for sub in subs_httpx_list:
            wt = webtech.WebTech(options={'json': True})

            try:
                report = wt.start_from_url(sub)

                retval = ""
                retval += "Target URL: {}\n".format(logger.bold_text(sub))

                if report['tech']:
                    retval += "\n\tDetected technologies:\n"
                for tech in report['tech']:
                    retval += "\t\t| {} {}\n".format(tech['name'], '' if tech['version'] is None else tech['version'])
                if report['headers']:
                    retval += "\n\tDetected the following interesting custom headers:\n"
                    for header in report['headers']:
                        retval += "\t\t| {}: {}\n".format(header["name"], header["value"])

                logger.info(retval)

            except webtech.utils.ConnectionException:
                logger.error("Connection error for URL: {}\n".format(sub))
            except webtech.utils.WrongContentTypeException:
                logger.error("Error while parsing the content type attribute of the response\n")
            except Exception as ex:
                logger.error("Unable to scan the target: {}".format(ex))

    #################################################################################
    ##### RUNNING ARJUN
    #################################################################################

    # TODO Deprecated, revise it and fix it before running it
    if enable_module_arjun:
        logger.print_title("RUNNING HTTP PARAMETER DISCOVERY")

        for sub in subs_httpx_list:
            logger.info("Target URL: {}".format(sub))

            # Executing arjun process
            bash_command = "arjun -u {} --stable".format(sub)
            process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, bufsize=2)

            while process.poll() is None:
                line = process.stdout.readline()
                line = line.decode("utf-8").strip()

                if line:
                    if line.startswith("[*]"):
                        logger.info_indented(line)
                    elif line.startswith("[+]"):
                        logger.info_indented(line)
                    elif line.startswith("[-]"):
                        logger.info_indented(line)
                    elif line.startswith("[!]"):
                        logger.info_indented(line)

            output, error = process.communicate()

    #################################################################################
    ##### RUNNING ACTIVE WEB SPIDER
    #################################################################################

    if not enable_fast_mode:
        logger.print_title("RUNNING ACTIVE WEB SPIDER")
        
        spider_dynamic_urls_list = []
        spider_subs_list = []
        spider_telephone_numbers_list = []
        spider_emails_list = []

        # Executing blackwidow process
        bash_command = "sudo blackwidow -d {}".format(input_domain)
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, bufsize=2)

        # Reading output in realtime
        while process.poll() is None:
            line = process.stdout.readline()
            line = line.decode("utf-8").strip()
            sanitized_line = re.sub(r'\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))', '', line)

            if line:
                # Matching subdomains in bw output
                if sanitized_line.startswith("[+] Sub-domain found"):
                    sanitized_line = sanitized_line.replace("[+] Sub-domain found! ", "").strip()
                    if sanitized_line not in spider_subs_list:
                        spider_subs_list.append(sanitized_line)
                        logger.info_sub(text=sanitized_line, sub="subdomain")

                # Matching telephone numbers in bw output
                elif sanitized_line.startswith("[i] Telephone # found"):
                    sanitized_line = sanitized_line.replace("[i] Telephone # found! ", "").strip()
                    if sanitized_line not in spider_telephone_numbers_list:
                        spider_telephone_numbers_list.append(sanitized_line)
                        logger.info_sub(text=sanitized_line, sub="telephone")

                # Matching emails in bw output
                elif sanitized_line.startswith("[i] Email found"):
                    sanitized_line = sanitized_line.replace("[i] Email found! ", "").strip()
                    if sanitized_line not in spider_emails_list:
                        spider_emails_list.append(sanitized_line)
                        logger.info_sub(text=sanitized_line, sub="email")

                # Matching dynamic URLs in bw output
                elif sanitized_line.startswith("[+] Dynamic URL found"):
                    sanitized_line = sanitized_line.replace("[+] Dynamic URL found! ", "").strip()
                    if sanitized_line not in spider_dynamic_urls_list:
                        spider_dynamic_urls_list.append(sanitized_line)
                        logger.info_sub(text=sanitized_line, sub="url")

        output, error = process.communicate()

        print("\n")
        # Printing stats
        logger.info(logger.bold_text("WEB SPIDER STATS:"))
        logger.info("Dynamic URLs found: {}".format(len(spider_dynamic_urls_list)))
        logger.info("Telephone # found: {}".format(len(spider_telephone_numbers_list)))
        logger.info("Emails found: {}".format(len(spider_emails_list)))
        logger.info("Subdomains found: {}".format(len(spider_subs_list)))

        # Executing cp command (copying the blackwidow output for dynamic URLs to the local loot)
        bash_command = ("cp /usr/share/blackwidow/{}_80/{}_80-dynamic-unique.txt {}").format(input_domain, input_domain,
                                                                                             OUT_LOCAL_LOOT + OUT_FILE_WEB_SPIDER)
        process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, bufsize=2)
        output, error = process.communicate()

        # Appending dynamic URLs discovered by bw to the input file for nuclei
        with open(OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE_HTTPX, "a", encoding="utf-8") as subs:

            bw_dynamic_unique_file = open(OUT_LOCAL_LOOT + OUT_FILE_WEB_SPIDER, "r", encoding="utf-8")
            lines = bw_dynamic_unique_file.readlines()
            subs.writelines([l for l in lines])
            bw_dynamic_unique_file.close()

            logger.info("Total selected URLs to add to list of targets: {}".format(len(lines)))

    #################################################################################
    ##### VULNERABILITY SCANNING
    #################################################################################

    logger.print_title("VULNERABILITY SCANNING")

    # Executing nuclei process
    bash_command = "nuclei -l {} -sa -s medium,high,critical,unknown".format(
        OUT_LOCAL_LOOT_SUBS + OUT_FILE_ALL_SUBS_UNIQUE_HTTPX)
    process = subprocess.Popen(bash_command.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=2)

    nuclei_count_unknown = 0
    nuclei_count_high = 0
    nuclei_count_critical = 0
    nuclei_count_medium = 0
    nuclei_count_info = 0

    nuclei_list_unknown = []
    nuclei_list_high = []
    nuclei_list_critical = []
    nuclei_list_medium = []
    nuclei_list_info = []
    nuclei_list_general_color = []
    nuclei_list_general_plain = []
    count_err_lines = 0

    logger.info("Starting vulnerability scanning")

    # Reading output in realtime
    while process.poll() is None:
        # for line in iter(process.stdout.readline, b''):
        # Reading lines and sanitizing output in stdout
        line = process.stdout.readline()
        line = line.decode("utf-8").strip()
        sanitized_line = re.sub(r'\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))', '', line)

        if line:
            # Collecting output lines in plain and colored mode
            nuclei_list_general_color.append(line)
            nuclei_list_general_plain.append(sanitized_line)

            if "[info]" in sanitized_line:
                logger.info(text=line, label=False)
                nuclei_count_info += 1
                nuclei_list_info.append(sanitized_line)

            elif "[medium]" in sanitized_line:
                logger.info(text=line, label=False)
                nuclei_count_medium += 1
                nuclei_list_medium.append(sanitized_line)

            elif "[high]" in sanitized_line:
                logger.info(text=line, label=False)
                nuclei_count_high += 1
                nuclei_list_high.append(sanitized_line)

            elif "[critical]" in sanitized_line:
                logger.info(text=line, label=False)
                nuclei_count_critical += 1
                nuclei_list_critical.append(sanitized_line)

            elif "[unknown]" in sanitized_line:
                logger.info(text=line, label=False)
                nuclei_count_unknown += 1
                nuclei_list_unknown.append(sanitized_line)

            elif "[INF]" in sanitized_line:
                logger.info(text=line, label=False)

            elif "[ERR]" in sanitized_line:
                logger.info(text=line, label=False)

    logger.info("Finishing scanning...")
    output, error = process.communicate()

    with open(OUT_LOCAL_LOOT_NUCLEI + OUT_FILE_NUCLEI_COLOR, "w", encoding="utf-8") as nf:
        for entry in nuclei_list_general_color:
            nf.write(entry + "\n")

    with open(OUT_LOCAL_LOOT_NUCLEI + OUT_FILE_NUCLEI_PLAIN, "w", encoding="utf-8") as nf:
        for entry in nuclei_list_general_plain:
            nf.write(entry + "\n")

    #################################################################################
    ##### [SYNC] ENUMERATING PUBLIC RESOURCES IN AWS, AZURE, GOOGLE CLOUD")
    #################################################################################

    if enable_module_cloud_enum:
        logger.print_title("ENUMERATING PUBLIC RESOURCES IN AWS, AZURE, GOOGLE CLOUD")

        # Reading output in realtime
        while process_cloud.poll() is None:

            line = process_cloud.stdout.readline()
            line = line.decode("utf-8").strip()
            sanitized_line = re.sub(r'\x1b(\[.*?[@-~]|\].*?(\x07|\x1b\\))', '', line)

            # Parsing the output line
            if line:

                if "amazon checks" in line:
                    logger.info("Checking resources in AWS")

                elif "azure checks" in line:
                    logger.info("Checking resources in Azure")

                elif "google checks" in line:
                    logger.info("Checking resources in Google cloud")

                elif "[+] Checking for" in line:
                    logger.info(line.replace("[+] ", ""))

                elif "[*] Testing" in line:
                    logger.info(line.replace("[*] ", ""))

                elif "[!] Timeout" in line:
                    start_index = line.find("Timeout")
                    line = line[start_index:]
                    logger.info_indented(line)

                elif "Elapsed time" in line:
                    logger.info_indented(line.strip() + "\n")

                elif "[+] Mutations list imported" in line:
                    logger.info(line.replace("[+] ", ""))

                elif "[+] Mutated results" in line:
                    logger.info(line.replace("[+] ", ""))

                elif "http" in line or "http" in sanitized_line:
                    logger.info(line)

        output, error = process_cloud.communicate()

    logger.print_title("SCAN COMPLETED!")


