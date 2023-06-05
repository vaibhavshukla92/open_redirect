import requests
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from termcolor import colored
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parameters = [
    "?next=",
    "?url=",
    "?target=",
    "?rurl=",
    "?dest=",
    "?destination=",
    "?redir=",
    "?redirect_uri=",
    "?redirect_url=",
    "?redirect=",
    "/redirect/",
    "/cgi-bin/redirect.cgi?",
    "/out/",
    "/out?",
    "?view=",
    "/login?to=",
    "?image_url=",
    "?go=",
    "?return=",
    "?returnTo=",
    "?return_to=",
    "?checkout_url=",
    "?continue=",
    "?return_path=",
    "success=",
    "data=",
    "qurl=",
    "login=",
    "logout=",
    "ext=",
    "clickurl=",
    "goto=",
    "rit_url=",
    "forward_url=",
    "forward=",
    "pic=",
    "callback_url=",
    "jump=",
    "jump_url=",
    "click?u=",
    "originUrl=",
    "origin=",
    "Url=",
    "desturl=",
    "u=",
    "page=",
    "u1=",
    "action=",
    "action_url=",
    "Redirect=",
    "sp_url=",
    "service=",
    "recurl=",
    "j?url=",
    "url=",
    "uri=",
    "u=",
    "allinurl:",
    "q=",
    "link=",
    "src=",
    "tc?src=",
    "linkAddress=",
    "location=",
    "burl=",
    "request=",
    "backurl=",
    "RedirectUrl=",
    "Redirect=",
    "ReturnUrl=",
    "redirecturl="
]

redirection_website = "https://www.google.com"

try:
    with open('urls.txt', 'r', encoding='latin-1') as file:
        urls = file.read().splitlines()
except FileNotFoundError:
    print("urls.txt file not found or unable to open.")
    exit(1)

open_redirect_urls = []

for url in urls:
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        existing_params = set(query_params.keys()).intersection(parameters)

        if existing_params:
            for param in existing_params:
                query_params[param] = query_params[param][0] + redirection_website

            updated_query = urlencode(query_params, doseq=True)
            updated_url = urlunparse(parsed_url._replace(query=updated_query))

            response = requests.get(updated_url, allow_redirects=False, verify=False)
            if response.status_code == 302 and redirection_website in response.headers.get('Location', ''):
                open_redirect_urls.append(updated_url)
                print(colored(f"Open redirect vulnerability found: {updated_url}", 'red'))
            else:
                print(colored(f"No open redirect vulnerability: {updated_url}", 'green'))
        else:
            print(colored(f"Ignoring URL: {url} (No query parameters to test)", 'yellow'))
    except urllib3.exceptions.SSLError:
        print(colored(f"Ignoring URL due to SSL certificate error: {url}", 'yellow'))

if open_redirect_urls:
    with open('openredirect.txt', 'w') as file:
        file.write("\n".join(open_redirect_urls))
        print("URLs with open redirect vulnerabilities saved to openredirect.txt.")
else:
    print("No URLs with open redirect vulnerabilities found.")
