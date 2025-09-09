import requests
import pytz
import socket
import argparse
import sys
import os

from datetime import datetime
from colorama import *
from rich.console import Console
from rich.table import Table

API_PUBLIC_IP = "https://api.ipify.org?format=json"
API_GET_LOCATION = "http://ip-api.com/json"


def windows_OS ():
    if os.name == 'nt':
        return init()
    
    
def get_public_ip():
    
    try:
        response = requests.get(API_PUBLIC_IP,timeout=5)
    except Exception as e:
        print(f"[-] ERROR API : {e}")    
        return None
    
    return response.json().get("ip")

    
def resolve_domain(domain_name):
    
    try:
        ip_address = socket.gethostbyname(domain_name)
        
    except Exception as e:
        print(f"[-] ERROR Domain: {e}")
        return None
    
    return ip_address
        
        
def get_ip_location_and_waf(ip):
    #Location
    url = f"{API_GET_LOCATION}/{ip}"
    try:
        response_location = requests.get(url,timeout=5,verify=False)
        data = response_location.json()
    except Exception as e:
        print(f"[-] ERROR GET LOCATION : {e}")
        return None
    
    
    #waf detect
    WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare", "__cfduid", "__cf_bm"],
    "Akamai": ["akamai", "akamai-ghost", "akamaighost", "ak_bmsc"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva / Incapsula": ["incapsula", "x-iinfo", "x-cdn"],
    "F5 BIG-IP": ["bigipserver", "f5", "x-waf-status"],
    "AWS WAF": ["awswaf", "x-amz-cf-id", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity", "x-mod-security", "x-powered-by-modsecurity"],
    "Barracuda": ["barra", "barracuda", "barra-counter"],
    "Citrix Netscaler": ["citrix", "ns_af"],
    "Fortinet FortiWeb": ["fortiwafsid", "fortinet", "fortiweb"],
    "Palo Alto Networks": ["paloalto", "x-paloalto"],
    "Azure WAF": ["azure", "x-azure-ref", "x-azure-socketip"],
    "Google Cloud Armor": ["x-cloud-armor"],
    "StackPath": ["stackpath", "sp-request-id"],
    "Fastly": ["fastly", "x-fastly-request-id"],
    "SiteGround": ["siteground", "sg-optimizer"],
    "Radware": ["radware", "x-rdwr"],
    "Check Point AppWall": ["appwall", "x-cp-appwall-action"],
    "Wallarm": ["wallarm", "x-wallarm-mode"],
    "Reblaze": ["reblaze", "rbzid"],
    "Cloudbric": ["cloudbric", "x-cloudbric-id"],
    "BlazingFast": ["blazingfast", "bf-cdn"],
    "NSFocus": ["nsfocus"],
    "Trustwave": ["trustwave", "tswaf"],
    "Alibaba Cloud WAF": ["aliwaf", "x-aliwaf-id"],
    "Generic WAF": ["x-waf", "x-firewall", "x-protected-by"]
}
    
    urls = [f"http://{ip}",f"https://{ip}"]
    headers = {}
    
    detected_waf = []
    for url_only in urls:
        try:
            response_waf = requests.get(url_only,timeout=3,verify=False)
            headers = {k.lower():v.lower() for k,v in response_waf.headers.items()}
            break
        except requests.RequestException:
            continue 
    
    for waf_name ,signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if any(sig in v for k,v in headers.items()):
                detected_waf.append(waf_name)
                
    
    if detected_waf:
        data['waf_list'] = detected_waf
    else:
        data['waf_list'] = [f"{Fore.RED}Not detected{Fore.RESET}"]
        
            
    return data

    

def show_display(data,original_input):
    
    #Time zone
    try:
        time_zone = pytz.timezone(data['timezone'])
        local_time = datetime.now(time_zone).strftime("%Y-%m-%d %H:%M:%S")
    except Exception as e:
        local_time = "Unavailable"
        
    
        
    table = Table(title="IP Location Information",title_style="bold cyan",show_lines=False)
    console = Console()
    #Header Table 
    table.add_column("LIST",style="bold yellow",justify="right")
    table.add_column("Value",style="green",justify='left')
    
    """print(f"{Fore.YELLOW}Input            {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{original_input}{Fore.RESET}")
    print(f"{Fore.YELLOW}IP Address       {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['query']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Country Code     {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['countryCode']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Country          {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['country']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Date & Time      {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{local_time}{Fore.RESET}")
    print(f"{Fore.YELLOW}Region Code      {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['region']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Region / City    {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['regionName']} / {data['city']}{Fore.RESET}")
    print(f"{Fore.YELLOW}ZIP Code         {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['zip']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Time Zone        {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['timezone']}{Fore.RESET}")
    print(f"{Fore.YELLOW}ISP              {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['isp']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Organization ASN {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['as']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Organization     {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['org']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Latitude         {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['lat']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Longitude        {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}{data['lon']}{Fore.RESET}")
    print(f"{Fore.YELLOW}Google Maps      {Fore.RESET}{Fore.RED}->{Fore.RESET} {Fore.GREEN}https://www.google.com/maps?q={data['lat']},{data['lon']}{Fore.RESET}")"""
    
    table.add_row("Input", original_input)
    table.add_row("Status",data['status'])
    table.add_row("IP Address", data['query'])
    table.add_row("Country Code", data['countryCode'])
    table.add_row("Country", data['country'])
    table.add_row("Date & Time", local_time)
    table.add_row("Region Code", data['region'])
    table.add_row("Region / City", f"{data['regionName']} / {data['city']}")
    table.add_row("ZIP Code", data['zip'])
    table.add_row("Time Zone", data['timezone'])
    table.add_row("ISP", data['isp'])
    table.add_row("WAF Detected", ", ".join(data['waf_list']))
    table.add_row("Organization ASN", data['as'])
    table.add_row("Organization", data['org'])
    table.add_row("Latitude", str(data['lat']))
    table.add_row("Longitude", str(data['lon']))
    table.add_row("Location",f"{str(data['lat'])},{str(data['lon'])}")
    table.add_row("Google Maps", f"https://www.google.com/maps?q={data['lat']},{data['lon']}")
    
    
    console.print(table)
    
    print("\n===============================================================\n")
    
    
    
def logo():
    logo_lines = [
        " ██████╗    █████╗   ██████╗  ██╗   ██╗ ██╗  ██╗  ██████╗   ██████╗  ██╗  ██╗",
        " ██╔══██╗  ██╔══██╗  ██╔══██╗ ╚██╗ ██╔╝ ██║  ██║ ██╔═══██╗ ██╔═══██╗ ██║ ██╔╝",
        " ██████╔╝  ███████║  ██████╔╝  ╚████╔╝  ███████║ ██║   ██║ ██║   ╚═╝ █████═╝ ",
        " ██╔══██╗  ██╔══██║  ██╔══██╗   ╚██╔╝   ██╔══██║ ██║ █ ██║ ██║       ██╔ ██╗ ",
        " ██████╔╝  ██║  ██║  ██████╔╝    ██║    ██║  ██║ ██║ ████║ ██║   ██╗ ██╔══██╗",
        " ╚═════╝   ╚═╝  ╚═╝  ╚═════╝     ╚═╝    ╚═╝  ╚═╝  ╚══╝╚══╝ ╚██████╔╝ ╚═╝  ╚═╝",
        "                                                     (FINDIP_LOCATION_V1.8)"
    ]
    
    return "\n".join([Fore.CYAN + line + Style.RESET_ALL for line in logo_lines])+"\n"
        
        
def infomation():
    
    width = 60
    
    version = "1.8"
    dev_by = "BabyH@ck"
    facebook = "https://www.facebook.com/thanawee321"
    organization = "https://www.youtube.com/@BabyHackSenior"
    

    # สร้างกรอบและเก็บในตัวแปร
    result = []
    
    edge = "=" + Fore.WHITE
    
    # ขอบบน
    result.append(edge * width)
    result.append(edge + " " * (width - 2) + edge)  # บรรทัดว่าง
    
    
    # ข้อความชิดซ้าย
    title_text = f"\tTool Find Location with IP Address".ljust(width - 8)
    version_text = f" Version       : {version}".ljust(width - 2)
    dev_by_text = f" DevBy         : {dev_by}".ljust(width - 2)
    aboutme = f" Facebook      : {facebook}".ljust(width - 2)
    company = f" Organization  : {organization}".ljust(width - 2)
    
    result.append(edge + title_text + edge)
    result.append(edge + version_text + edge)
    result.append(edge + dev_by_text + edge)
    result.append(edge + aboutme + edge)
    result.append(edge + company + edge)
    result.append(edge + " " * (width - 2) + edge)  # บรรทัดว่าง
    result.append(edge + " " * (width - 2) + edge)  # บรรทัดว่าง
    result.append(edge * width + Fore.RESET)  # ขอบล่าง

    # รวมข้อความทั้งหมดเป็นสตริงเดียว
    border_content = "\n".join(result)

    # ผลลัพธ์ที่ประกอบกันเป็น ASCII Art และกรอบ
    return logo() + "\n" + border_content + "\n"
    

def error_message():
    print(f"\n{Fore.RED}Can't check {Fore.RESET}IP Address or Domain name!!\n{Fore.RED}Please check internet connection!!{Fore.RESET}\n{Fore.RED}Please check your command!!{Fore.RESET}")
    
def get_parser():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target",help="IP Address or Domain")
    parser.add_argument("-m","--myip",action='store_true',help="Check IP Address myself")
    
    return parser
    
def main():
    
    print(infomation())
    
    parser = get_parser()
    args = parser.parse_args()
    
    try:
        
        if args.myip:
            my_ip = get_public_ip()
            
            if not my_ip:
                sys.exit(1)
                
            data = get_ip_location_and_waf(my_ip)
            
            if data:
                #hostname = socket.gethostname()
                show_display(data,original_input = "My Device")
                
        elif args.target:
            target = args.target.strip()
            if not target.replace('.','').isdigit():
                ip_address = resolve_domain(target)
                
            else:
                ip_address = target
                
            data = get_ip_location_and_waf(ip_address)
            if data:
                show_display(data,original_input=target)
                
        elif not args.target and not args.myip:
            parser.print_help()
            error_message()
            sys.exit(1)
                
            
    except Exception as e:
        print(f"ERROR : {e}")
    
    

if __name__ == '__main__':
    windows_OS()
    main()