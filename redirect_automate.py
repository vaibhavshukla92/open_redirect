import re
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable insecure request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# List of parameter names
parameter_names = [
    'url', 'target', 'rurl', 'dest', 'destination', 'redir', 'redirect_uri',
    'redirect_url', 'redirect', '/redirect/', '/cgi-bin/redirect.cgi', '/out/',
    '/out', 'view', '/loginto', 'image_url', 'go', 'return', 'returnTo',
    'return_to', 'checkout_url', 'continue', 'return_path', 'success', 'data',
    'qurl', 'login', 'logout', 'ext', 'clickurl', 'goto', 'rit_url',
    'forward_url', 'forward', 'pic', 'callback_url', 'jump', 'jump_url',
    'clicku', 'originUrl', 'origin', 'Url', 'desturl', 'u', 'page', 'u1',
    'action', 'action_url', 'Redirect', 'sp_url', 'service', 'recurl',
    'j?url', 'url=//', 'uri', 'u', 'allinurl:', 'q', 'link', 'src', 'tc?src',
    'linkAddress', 'location', 'burl', 'request', 'backurl', 'RedirectUrl',
    'Redirect', 'ReturnUrl', 'redirecturl'
]

# Read URLs from file
with open('urls.txt', 'r') as file:
    urls = file.read().splitlines()

# Check URLs for keywords and test for open redirection
for url in urls:
    found_keyword = False
    redirect_url = 'https://www.google.com'

    # Check if URL contains any keyword
    for keyword in parameter_names:
        pattern = r'([?&])(' + re.escape(keyword) + r'=)'
        match = re.search(pattern, url)

        if match:
            found_keyword = True
            url = re.sub(r'(\?|&)' + re.escape(keyword) + '=([^&]*)', r'\1' + keyword + '=' + redirect_url, url)
            break

    if found_keyword:
        # Test for open redirection by redirecting to www.google.com
        try:
            response = requests.get(url, allow_redirects=False, verify=False)
        except requests.exceptions.RequestException as e:
            print('\033[91m[Error]\033[0m', url, '--', str(e))
            continue

        # Analyze the response to determine vulnerability
        if response.status_code == 302 and redirect_url in response.headers.get('Location', ''):
            print('\033[91m[Vulnerable]\033[0m', url)  # Print in red for vulnerable ones
        else:
            if response.status_code == 301 and redirect_url in response.headers.get('Location', ''):
                print('\033[91m[Vulnerable]\033[0m', url)  # Print in red for vulnerable ones
            else: 
                print('\033[92m[Non-Vulnerable]\033[0m', url)  # Print in green for non-vulnerable ones
    else:
        print('\033[97m[Ignored]\033[0m', url)  # Print in white for ignored ones

    # Reset the found_keyword flag
    found_keyword = False
