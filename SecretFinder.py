#!/usr/bin/env python
# SecretFinder - Tool for discover apikeys/accesstokens and sensitive data in js file
# based on LinkFinder - github.com/GerbenJavado
# By m4ll0k (@m4ll0k2) github.com/m4ll0k

import os
import sys
if not sys.version_info.major >= 3:
    print("[ + ] Run this tool with python version 3.+")
    sys.exit(0)
os.environ["BROWSER"] = "open"

import re
import glob
import argparse
import jsbeautifier
import webbrowser
import subprocess
import base64
import requests
import string
import random
from html import escape
import urllib3
import xml.etree.ElementTree
# disable warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# for read local file with file:// protocol
from requests_file import FileAdapter
from lxml import html
from urllib.parse import urlparse

# regex
_regex = {
    'google_api': r'AIza[0-9A-Za-z-_]{35}',
    'firebase': r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha': r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth': r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id': r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url': r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2': r"(" \
                      r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
                      r"|s3://[a-zA-Z0-9-\.\_]+" \
                      r"|s3-[a-zA-Z0-9-\.\_\/]+" \
                      r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
                      r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token': r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic': r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer': r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api': r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key': r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key': r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid': r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid': r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token': r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret': r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token': r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api': r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api': r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token': r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key': r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key': r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key': r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token': r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token': r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey': r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY': r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds': r"(?i)(" \
                      r"password\s*[`=:\"]+\s*[^\s]+|" \
                      r"password is\s*[`=:\"]*\s*[^\s]+|" \
                      r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                      r"passwd\s*[`=:\"]+\s*[^\s]+)",
}

_template = '''
  LinkFinder Output
  $$content$$


'''

def parser_error(msg):
    print('Usage: python %s [OPTIONS] use -h for help' % sys.argv[0])
    print('Error: %s' % msg)
    sys.exit(0)


def getContext(matches, content, name, rex='.+?'):
    ''' get context '''
    items = []
    matches2 = []
    for i in [x[0] for x in matches]:
        if i not in matches2:
            matches2.append(i)
    for m in matches2:
        context = re.findall('%s%s%s' % (rex, m, rex), content, re.IGNORECASE)
        item = {
            'matched': m,
            'name': name,
            'context': context,
            'multi_context': True if len(context) > 1 else False
        }
        items.append(item)
    return items


def parser_file(content, mode=1, more_regex=None, no_dup=1):
    ''' parser file '''
    if mode == 1:
        if len(content) > 1000000:
            content = content.replace(";", ";\r\n").replace(",", ",\r\n")
        else:
            content = jsbeautifier.beautify(content)
    all_items = []
    for regex in _regex.items():
        r = re.compile(regex[1], re.VERBOSE | re.I)
        if mode == 1:
            all_matches = [(m.group(0), m.start(0), m.end(0)) for m in re.finditer(r, content)]
            items = getContext(all_matches, content, regex[0])
            if items != []:
                all_items.append(items)
        else:
            items = [{'matched': m.group(0), 'context': [], 'name': regex[0], 'multi_context': False}
                     for m in re.finditer(r, content)]
            if items != []:
                all_items.append(items)
    if all_items != []:
        k = []
        for i in range(len(all_items)):
            for ii in all_items[i]:
                if ii not in k:
                    k.append(ii)
        if k != []:
            all_items = k
    if no_dup:
        all_matched = set()
        no_dup_items = []
        for item in all_items:
            if item != [] and type(item) is dict:
                if item['matched'] not in all_matched:
                    all_matched.add(item['matched'])
                    no_dup_items.append(item)
        all_items = no_dup_items
    filtered_items = []
    if all_items != []:
        for item in all_items:
            if more_regex:
                if re.search(more_regex, item['matched']):
                    filtered_items.append(item)
            else:
                filtered_items.append(item)
    return filtered_items


def parser_input(input):
    ''' Parser Input
        This function returns a list of URLs or "file://..." entries
        Supports:
         - direct URL string
         - view-source:
         - burp xml (handled separately)
         - wildcard glob
         - local file path (single JS file)
         - local file that contains a list of URLs (one per line) -> returns those URLs
    '''
    # method 1 - url schemes
    schemes = ('http://', 'https://', 'ftp://', 'file://', 'ftps://')
    if input.startswith(schemes):
        return [input]

    # method 2 - url inspector firefox/chrome
    if input.startswith('view-source:'):
        return [input[12:]]

    # method 3 - Burp file (handled elsewhere based on args.burp)
    # method 4 - folder with a wildcard
    if '*' in input:
        paths = glob.glob(os.path.abspath(input))
        for index, path in enumerate(paths):
            paths[index] = "file://%s" % path
        return (paths if len(paths) > 0 else parser_error('Input with wildcard does not match any files.'))

    # method 5 - local file: either a JS file to scan, or a file that contains multiple URLs
    if os.path.exists(input) and os.path.isfile(input):
        # Read the file content to determine if it contains lines that look like URLs
        try:
            with open(input, 'r', encoding='utf-8', errors='ignore') as fh:
                data = fh.read()
        except Exception as e:
            return parser_error('Could not read file: %s' % e)

        # If file looks like Burp XML and args.burp will be used later, return the path (burp handled later)
        # If the file contains many lines and lines start with http(s) treat it as URL list
        lines = [line.strip() for line in data.splitlines() if line.strip()]
        url_like = [ln for ln in lines if ln.startswith(('http://', 'https://', 'ftp://', 'ftps://'))]

        if len(url_like) >= 1 and len(url_like) == len(lines):
            # file is a list of URLs (one per line)
            return url_like
        else:
            # treat as a single local JS file
            path = "file://%s" % os.path.abspath(input)
            return [path]

    return parser_error('file could not be found (maybe you forgot to add http/https).')


def html_save(output):
    ''' html output '''
    hide = os.dup(1)
    os.close(1)
    os.open(os.devnull, os.O_RDWR)
    try:
        text_file = open(args.output, "wb")
        text_file.write(_template.replace('$$content$$', output).encode('utf-8'))
        text_file.close()
        print('URL to access output: file://%s' % os.path.abspath(args.output))
        file = 'file:///%s' % (os.path.abspath(args.output))
        if sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.call(['xdg-open', file])
        else:
            webbrowser.open(file)
    except Exception as err:
        print('Output can\'t be saved in %s due to exception: %s' % (args.output, err))
    finally:
        os.dup2(hide, 1)


def cli_output(matched):
    ''' cli output '''
    for match in matched:
        print(match.get('name') + '\t->\t' + match.get('matched').encode('ascii', 'ignore').decode('utf-8'))


def urlParser(url):
    ''' urlParser '''
    parse = urlparse(url)
    urlParser.this_root = parse.scheme + '://' + parse.netloc
    urlParser.this_path = parse.scheme + '://' + parse.netloc + '/' + parse.path


def extractjsurl(content, base_url):
    ''' JS url extract from html page '''
    soup = html.fromstring(content)
    all_src = []
    urlParser(base_url)
    for src in soup.xpath('//script'):
        # some script tags may not have src attribute
        s = src.xpath('@src')
        if not s:
            continue
        src = s[0]
        if src.startswith(('http://', 'https://', 'ftp://', 'ftps://')):
            if src not in all_src:
                all_src.append(src)
        elif src.startswith('//'):
            src2 = 'http://' + src[2:]
            if src2 not in all_src:
                all_src.append(src2)
        elif src.startswith('/'):
            src2 = urlParser.this_root + src
            if src2 not in all_src:
                all_src.append(src2)
        else:
            src2 = urlParser.this_path + src
            if src2 not in all_src:
                all_src.append(src2)

    if args.ignore and all_src != []:
        temp = list(all_src)
        ignore = []
        for i in args.ignore.split(';'):
            for s in all_src:
                if i in s:
                    ignore.append(s)
        if ignore:
            for i in ignore:
                if i in temp:
                    temp.pop(int(temp.index(i)))
        return temp

    if args.only:
        temp = list(all_src)
        only = []
        for i in args.only.split(';'):
            for s in all_src:
                if i in s:
                    only.append(s)
        return only

    return all_src


def send_request(url):
    ''' Send Request '''
    # read local file
    # https://github.com/dashea/requests-file
    if 'file://' in url:
        s = requests.Session()
        s.mount('file://', FileAdapter())
        return s.get(url).content.decode('utf-8', 'replace')

    # set headers and cookies
    headers = {}
    default_headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.8',
        'Accept-Encoding': 'gzip'
    }

    if args.headers:
        for i in args.headers.split('\\n'):
            # replace space and split
            name, value = i.replace(' ', '').split(':', 1)
            headers[name] = value

    # add cookies
    if args.cookie:
        headers['Cookie'] = args.cookie

    headers.update(default_headers)

    # proxy
    proxies = {}
    if args.proxy:
        proxies.update({
            'http': args.proxy,
            'https': args.proxy,
        })

    try:
        resp = requests.get(
            url=url,
            verify=False,
            headers=headers,
            proxies=proxies
        )
        return resp.content.decode('utf-8', 'replace')
    except Exception as err:
        print(err)
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-e", "--extract", help="Extract all javascript links located in a page and process it", action="store_true", default=False)
    parser.add_argument("-i", "--input", help="Input a: URL, file or folder", required="True", action="store")
    parser.add_argument("-o", "--output", help="Where to save the file, including file name.\nDefault: output.html", action="store", default="output.html")
    parser.add_argument("-r", "--regex", help="RegEx for filtering purposes against found endpoint (e.g: ^/api/)", action="store")
    parser.add_argument("-b", "--burp", help="Support burp exported file", action="store_true")
    parser.add_argument("-c", "--cookie", help="Add cookies for authenticated JS files", action="store", default="")
    parser.add_argument("-g", "--ignore", help="Ignore js url, if it contain the provided string (string;string2..)", action="store", default="")
    parser.add_argument("-n", "--only", help="Process js url, if it contain the provided string (string;string2..)", action="store", default="")
    parser.add_argument("-H", "--headers", help="Set headers (\"Name:Value\\nName:Value\")", action="store", default="")
    parser.add_argument("-p", "--proxy", help="Set proxy (host:port)", action="store", default="")
    args = parser.parse_args()

    if args.input[-1:] == "/":
        # /aa/ -> /aa
        args.input = args.input[:-1]

    mode = 1
    if args.output == "cli":
        mode = 0

    # add args regex validation
    if args.regex:
        try:
            r = re.search(args.regex, ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(10, 50))))
        except Exception as e:
            print('your python regex isn\'t valid')
            sys.exit()
        _regex.update({'custom_regex': args.regex})

    if args.extract:
        # extract js links from the page(s) provided
        # args.input may be a file with multiple URLs, parser_input handles that
        inputs = parser_input(args.input)
        # when extract flag is used, treat each input as a page to fetch and extract js links from
        js_targets = []
        for inp in inputs:
            try:
                content = send_request(inp)
            except Exception as e:
                print(f"[-] Failed to fetch {inp}: {e}")
                continue
            found = extractjsurl(content, inp)
            for f in found:
                if f not in js_targets:
                    js_targets.append(f)
        urls = js_targets
    elif args.burp:
        # Burp XML file: parser_input will return the file path as file://..., but burp logic expects reading the XML
        # We'll read the provided file directly as burp XML
        jsfiles = []
        items = []
        try:
            tree = xml.etree.ElementTree.fromstring(open(args.input, 'r').read())
        except Exception as err:
            print(err)
            sys.exit()
        for item in tree:
            jsfiles.append({
                'js': base64.b64decode(item.find('response').text).decode('utf-8', 'replace'),
                'url': item.find('url').text
            })
        urls = jsfiles
    else:
        # convert input to URLs or JS files (supports list of URLs in a file)
        urls = parser_input(args.input)

    output = ''
    for url in urls:
        # When burp mode, url may be dict with 'js' and 'url'
        print('[ + ] URL: ' + (url.get('url') if isinstance(url, dict) else url))
        if not args.burp:
            try:
                file = send_request(url)
            except Exception as e:
                print(f"[-] Failed to fetch {url}: {e}")
                continue
        else:
            file = url.get('js')
            url = url.get('url')

        matched = parser_file(file, mode)
        if args.output == 'cli':
            cli_output(matched)
        else:
            #output += '\n# File: \n\n' % (escape(url))
            output += '\n# File: %s\n\n' % (escape(url))
            for match in matched:
                _matched = match.get('matched')
                _named = match.get('name')
                header = '\n\n## %s\n' % (_named.replace('_', ' '))
                body = ''
                # find same thing in multiple context
                if match.get('multi_context'):
                    no_dup = []
                    for context in match.get('context'):
                        if context not in no_dup:
                            body += '\n\n%s\n\n' % (context)
                            no_dup.append(context)
                else:
                    body += '\n\n%s\n\n' % (match.get('context')[0] if len(match.get('context')) > 0 else ''.join(match.get('context')))
                output += header + body

    if args.output != 'cli' and output:
        html_save(output)
