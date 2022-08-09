from array import array
from importlib.resources import path

import pandas as pd
import os
import ipaddress
import numpy as np
from urllib.parse import urlparse, urlsplit, parse_qs
import whois
from datetime import datetime
import socket
import pydig
import certifi
import urllib3
from cymruwhois import Client
from selenium import webdriver
from random import randint, randrange
import tldextract
import dns
import dns.name
import dns.query
import dns.resolver

import re
import requests
from requests.exceptions import ConnectionError
from bs4 import BeautifulSoup

import joblib
import pickle

# with open('forrestSample', 'rb') as f:
#     forrest = pickle.load(f)
forrest = joblib.load('model/forrestSample')
lg_4 = joblib.load('model/lgc_5')
rf_final = joblib.load('model/rf_final')

# load model from file
# loaded_model = pickle.load(open("model/lgc_2.pickle.dat", "rb"))



def qty_dot(url):
    return url.count('.')

def qty_hyphen(url):
    return url.count("-")

def qty_underline(url):
    return url.count('_')

def qty_slash(url):
    return url.count('/')

def qty_questionmark(url):
    return url.count('?')

def qty_equal(url):
    return url.count('=')

def qty_at(url):
    return url.count('@')

def qty_and(url):
    return url.count('&')

def qty_exclamation(url):
    return url.count('!')

def qty_space(url):
    return url.count(' ')

def qty_tilde(url):
    return url.count('~')

def qty_comma(url):
    return url.count(',')

def qty_plus(url):
    return url.count('+')

def qty_asterisk(url):
    return url.count('*')

def qty_hashtag(url):
    return url.count('#')

def qty_dollar(url):
    return url.count('$')

def qty_percent(url):
    return url.count('%')

def qty_tld_url(url):
    tld_url = tldextract.extract(url).suffix
    return len(tld_url)

def length_url(url):
    return len(url)


emailRegex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
 
def email_in_url(url):
    return 1 if (re.findall(emailRegex, url)) else 0

def qty_vowels_domain(url):
  vowels = ['a', 'e', 'i', 'o', 'u']
  return len([i for i in url if i in vowels])

def domain_length(url):
  return len(url)

def domain_in_ip(url):
  ipPattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
  try:
      mo = ipPattern.search(url).group()
      if ipaddress.ip_address(mo):
          ip = 1
  except Exception:
      ip = 0
  return ip

def server_client_domain(url):
  keyword = r"server|client"
  return 1 if (re.search(keyword,url)) else 0

def tld_present_params(url):
    return 1 if tldextract.extract(url).suffix else 0

def qty_params(url):
    return len(url.split("&")) if "&" in url else 1

def time_response(url):
    try:
        r = requests.get(url, timeout=2)
        r.raise_for_status()
        return round(r.elapsed.total_seconds(),7)
    except Exception:
        return 0

def domain_spf(url):
  try:
    test_spf = dns.resolver.resolve(url , 'TXT')
    for dns_data in test_spf:
      if 'spf1' in str(dns_data):
        return 1
  except Exception:
    return 0

def asn_ip(url):
    try:
        domainUrl = urlparse(url).hostname
        ip = socket.gethostbyname(domainUrl)
        c = Client()
        r = c.lookup(ip)
        return r.asn
    except Exception:
        return 0

def time_domain_activation(url):
  today = datetime.now()

  try:
    creation_date = whois.whois(urlparse(url).netloc).creation_date
  except Exception:
    return 0

  if isinstance(creation_date,list):
    creation_date = creation_date[0]

  if isinstance(creation_date,str):
    try:
      creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
      # expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
    except Exception:
      return 0
  if (creation_date is None) or type(creation_date) is list:
    return 0
  return abs((creation_date - today).days)

def time_domain_expiration(url):
  today = datetime.now()

  try:
    expiration_date = whois.whois(urlparse(url).netloc).expiration_date
  except Exception:
    return 0

  if isinstance(expiration_date,list):
    expiration_date = expiration_date[0]

  if isinstance(expiration_date,list):
    try:
        expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
        return expiration_date
    except Exception:
      return 0
  if (expiration_date is None) or type(expiration_date) is list:
    return 0
  return abs((today - expiration_date).days)


def qty_ip_resolved(url):
    try:
        domain = whois.whois(urlparse(url).netloc).domain_name
    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    try:
        ipAddress = socket.gethostbyname_ex(domain)
        return len(ipAddress[-1])
    except Exception:
        return 0

def qty_nameservers(url):
    try:
        nameServer = whois.whois(urlparse(url).netloc).name_servers
        # nameServer = 
    except Exception:
        return 0

    if nameServer is None:
        return 0
    if isinstance(nameServer,str):
        return 1

    return len(nameServer)

def qty_mx_servers(url):
    try:
        domain = whois.whois(urlparse(url).netloc).domain_name
        try:
            return len(dns.resolver.resolve(domain, 'MX'))
        except Exception:
            return 0
    except Exception:
        return 0




def get_authoritative_nameserver(domain, log=lambda msg: None):
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == u'@'
        sub = s[1]

        log('Looking up %s on %s' % (sub, nameserver))
        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, nameserver)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('%s does not exist.' % sub)
            else:
                raise Exception('Error %s' % dns.rcode.to_text(rcode))

        rrset = None
        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            log('Same server is authoritative for %s' % sub)
        else:
            authority = rr.target
            log('%s is authoritative for %s' % (authority, sub))
            nameserver = default.query(authority).rrset[0].to_text()

        depth += 1

    return authority


import sys

def log(msg):
    print (msg)

def ttl_hostname(url):
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['1.1.1.1']

    domain = urlparse(url).netloc
    # print (ns2.binus.ac.id.)
    try:
        ns = get_authoritative_nameserver(domain)
        # print(ns)
        # answer = my_resolver.query('ns1-05.azure-dns.com.')
        # my_resolver.query('ns2.binus.ac.id.').rrset.ttl
        return my_resolver.query(ns).rrset.ttl
    except Exception:
        return 0

def tls_ssl_certificate(url):
    try:
        r = requests.get(url, timeout=2)
        return 1 if r.status_code == 200 else 0
    # except (requests.exceptions.SSLError):
    #     # print(traceback.format_exc())
    #     return 0
    except Exception:
        return 0

def qty_redirects(url):
    try:
        response = requests.get(url, allow_redirects = True, timeout=2)
        # print(response.history)
        return sum(1 for _ in response.history)
        
    except requests.exceptions.SSLError:
        return 0
    except Exception:
        return 0

def indexed(url):
  

  google = f"https://www.google.com/search?q=site:{url}&hl=en"
  response = requests.get(google, cookies={"CONSENT": "YES+1"})
  soup = BeautifulSoup(response.content, "html.parser")
  not_indexed = re.compile("did not match any documents")

  return 0 if soup(text=not_indexed) else 1

def url_google_index(url):
  return indexed(url)

def domain_google_index(url):
  domainURL = urlparse(url).hostname
  return indexed(domainURL)

short_url = re.compile(r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
            r"tr\.im|link\.zip\.net")

def url_shortened(url):
    domain = urlparse(url).netloc
    return 1 if short_url.match(domain) else 0

# def featureExtract(url):

#   features = []

#   features.append(qty_dot(url))
#   features.append(qty_hyphen(url))
#   features.append(qty_underline(url))
#   features.append(qty_slash(url))

#   return features



def featureExtract(url):

  features = []

  features.append(qty_dot(url))
  features.append(qty_hyphen(url))
  features.append(qty_underline(url))
  features.append(qty_slash(url))
  features.append(qty_questionmark(url))
  features.append(qty_equal(url))
  features.append(qty_at(url))
  features.append(qty_and(url))
  features.append(qty_exclamation(url))
  features.append(qty_space(url))
  features.append(qty_tilde(url))
  features.append(qty_comma(url))
  features.append(qty_plus(url))
  features.append(qty_asterisk(url))
  features.append(qty_hashtag(url))
  features.append(qty_dollar(url))
  features.append(qty_percent(url))
  features.append(qty_tld_url(url))
  features.append(length_url(url))

  try:
    domainUrl = urlparse(url).hostname
  except Exception:
    domainUrl = 0
    
  features.append(0 if domainUrl == 0 else qty_dot(domainUrl))
  features.append(0 if domainUrl == 0 else qty_hyphen(domainUrl))
  features.append(0 if domainUrl == 0 else qty_underline(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_slash(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_questionmark(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_equal(domainUrl))
  features.append(0 if domainUrl == 0 else qty_at(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_and(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_exclamation(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_space(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_tilde(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_comma(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_plus(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_asterisk(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_hashtag(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_dollar(domainUrl))
#   features.append(0 if domainUrl == 0 else qty_percent(domainUrl))
  features.append(0 if domainUrl == 0 else qty_vowels_domain(domainUrl))
  features.append(0 if domainUrl == 0 else domain_length(domainUrl))
  features.append(0 if domainUrl == 0 else domain_in_ip(domainUrl))
  features.append(0 if domainUrl == 0 else server_client_domain(domainUrl))

  try:
    directoryUrl = os.path.dirname(urlparse(url).path)
    if not directoryUrl:
      directoryUrl = 0
  except Exception:
    directoryUrl = 0

  features.append(0 if directoryUrl == 0 else qty_dot(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_hyphen(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_underline(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_slash(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_questionmark(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_equal(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_at(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_and(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_exclamation(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_space(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_tilde(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_comma(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_plus(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_asterisk(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_hashtag(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_dollar(directoryUrl))
  features.append(0 if directoryUrl == 0 else qty_percent(directoryUrl))
  features.append(0 if directoryUrl == 0 else domain_length(directoryUrl))

  try:
    filenameUrl = os.path.basename(urlparse(url).path)
    if not filenameUrl:
      filenameUrl = 0
  except Exception:
    filenameUrl = 0

  features.append(0 if filenameUrl == 0 else qty_dot(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_hyphen(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_underline(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_slash(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_questionmark(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_equal(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_at(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_and(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_exclamation(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_space(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_tilde(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_comma(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_plus(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_asterisk(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_hashtag(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_dollar(filenameUrl))
  features.append(0 if filenameUrl == 0 else qty_percent(filenameUrl))
  features.append(0 if filenameUrl == 0 else domain_length(filenameUrl))

  try:
    parameterUrl = urlparse(url).query
    if not parameterUrl:
      parameterUrl = 0
  except Exception:
    parameterUrl = 0

  features.append(0 if parameterUrl == 0 else qty_dot(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_hyphen(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_underline(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_slash(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_questionmark(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_equal(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_at(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_and(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_exclamation(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_space(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_tilde(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_comma(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_plus(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_asterisk(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_hashtag(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_dollar(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_percent(parameterUrl))
  features.append(0 if parameterUrl == 0 else domain_length(parameterUrl))
  features.append(0 if parameterUrl == 0 else tld_present_params(parameterUrl))
  features.append(0 if parameterUrl == 0 else qty_params(parameterUrl))
  features.append(email_in_url(url))


  features.append(time_response(url))
  features.append(domain_spf(url))
  features.append(asn_ip(url))
  features.append(time_domain_activation(url))
  features.append(time_domain_expiration(url))
  features.append(qty_ip_resolved(url))
  features.append(qty_nameservers(url))
  features.append(qty_mx_servers(url))
  features.append(ttl_hostname(url))
  features.append(tls_ssl_certificate(url))
  features.append(qty_redirects(url))
  features.append(url_google_index(url))
  features.append(domain_google_index(url))
  features.append(url_shortened(url))

  return features






def whoisDomain(url):
    try:
        domain = whois.whois(urlparse(url).netloc).domain_name
    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    return domain

def whoisRegistrar(url):
    try:
        registrar = whois.whois(urlparse(url).netloc).registrar
    except Exception:
        return 0

    if registrar is None:
        return 0

    if isinstance(registrar,list):
        try:
            registrar = registrar[0]
        except Exception:
            return 0
    return registrar

def whoisNS(url):
    try:
        domain = whois.whois(urlparse(url).netloc).name_servers
    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    return domain

def whoisName(url):
    try:
        domain = whois.whois(urlparse(url).netloc).name

    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    return domain

def whoisOrg(url):
    try:
        domain = whois.whois(urlparse(url).netloc).org

    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    return domain

def whoisAddress(url):
    try:
        domain = whois.whois(urlparse(url).netloc).address

    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    return domain

def whoisCity(url):
    try:
        domain = whois.whois(urlparse(url).netloc).city

    except Exception:
        return 0

    if domain is None:
        return 0

    if isinstance(domain,list):
        try:
            domain = domain[0]
        except Exception:
            return 0
    return domain

def WhoisExpDate(url):
    try:
        expiration_date = whois.whois(urlparse(url).netloc).expiration_date
    except Exception:
        return 0

    try:
        return expiration_date.strftime("%m/%d/%Y, %H:%M:%S")
    except Exception:
        return 0

def WhoisCreationDate(url):
    try:
        creation_date = whois.whois(urlparse(url).netloc).expiration_date
    except Exception:
        return 0

    try:
        return creation_date.strftime("%m/%d/%Y, %H:%M:%S")
    except Exception:
        return 0



def predictURL(url):
    features = featureExtract(url)
    features = np.array(features, dtype=float)
    # features = features.reshape(1, -1)
    prediction = rf_final.predict([features])
    if prediction==1:
        prediction=True
        print(prediction)
    else:
        prediction= False
        print(prediction)
    return prediction

def validate_url(url):
    try:
        response = requests.get(url, timeout=10)
    except ConnectionError:
        return 0
    else:
        return 1


def get_screenshot(url):
    options = webdriver.ChromeOptions()
    options.add_argument('--ignore-certificate-errors')
    options.add_argument("--test-type")
    options.add_argument("--headless")
    options.add_argument("--window-size=1920,1080")
    # options.binary_location = "/usr/bin/chromium"
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        driver.save_screenshot("screenshot.png")
        driver.quit()
    except Exception:
        return 0
    driver.get(url)
    domain = urlparse(url).netloc
    id = randrange(10000000, 99999999)
    image_name = f"media/images/screenshot_{domain}_{id}.png"
    # print(image_name)
    driver.save_screenshot(image_name)

    driver.close()
    path = f"images/screenshot_{domain}_{id}.png"
    
    return image_name

def report(url, email):
    r = requests.post('https://report.netcraft.com/api/v2/report/urls', json={
        "email": email,
        "urls": [url],
    })
    message = r.json()
    return 1 if re.search("Successfully", message['message']) else 0