# Tested with Python 2.6.8
# download Request OAuthlib from https://github.com/requests/requests-oauthlib
from requests_oauthlib.oauth1_session import OAuth1Session
from datetime import datetime
import os.path
import json
import sys


# constants definitions
DEFAULT_JSON_HEADER = {'Accept': 'application/vnd.deere.axiom.v3+json'}


# function definitions
def read_store(store_pathname, store_name):
    data = None
    print 'Reading ' + store_name + ' store...'
    if os.path.isfile(store_pathname):
        if os.path.getsize(store_pathname) > 0:
            store = open(store_pathname, 'r')
            data = json.load(store)
            store.close()
    else:
        print store_name[0:1].upper() + store_name[1:] + ' store doesn\'t exist, creating...'
        store = open(store_pathname, 'w')
        print 'Created ' + store_name + ' store at "' + os.path.abspath(store.name) + '"'
        store.close()
    print 'Done reading ' + store_name + ' store.'
    return data


def write_store(store_pathname, store_name, data):
    print 'Updating ' + store_name + ' store...'
    store = open(store_pathname, 'w')
    json.dump(data, store)
    store.close()
    print 'Done updating ' + store_name + ' store.'


def extract_link(json_object, relationship):
    links = json_object.get('links')
    extracted_link = None
    for link in links:
        if link.get('rel') == relationship:
            extracted_link = link.get('uri')
            break
    return extracted_link


def list_files(file_list):
    print 'Links:'
    print json.dumps(file_list.get('links'), indent=4, sort_keys=True)
    print 'Total: ' + str(file_list.get('total'))
    if int(file_list.get('total')) > 0:
        print 'File list:'
        values = file_list.get('values')
        print 'id'.rjust(10), 'name'.rjust(40), 'type'.rjust(15), 'source'.rjust(25), 'status'.rjust(15)
        for value in values:
            print value.get('id').rjust(10), value.get('name').rjust(40), value.get('type').rjust(15), value.get(
                'source').rjust(25), value.get('status').rjust(15)
    else:
        print 'File list empty.'


def handle_endpoint(this_choice, this_prev_response):
    _response = None
    _url = None
    if this_choice[0:1] == '/':
        _url = base_url + this_choice
    else:
        if prev_response is None:
            print 'Previous operation did not yield a browsable result, please enter an absolute path instead!'
        else:
            _url = extract_link(this_prev_response, this_choice)

    if _url is not None:
        _response = oauth_session.get(_url, headers=DEFAULT_JSON_HEADER).json()
        if len(_response) > 0:
            # handle file list more easily
            self_url = extract_link(_response, 'self')
            if self_url is not None and 'files' in self_url and _response.get('values') is not None:
                list_files(_response)
            else:
                print json.dumps(_response, indent=4, sort_keys=True)
        else:
            print 'Response is empty. Nothing to display.'

    return _response


# some basic declarations
base_url = 'https://apicert.soa-proxy.deere.com/platform'
credentials_store_name = 'credentials_store'
token_store_name = 'token_store'

# 1) oob displays a code instead of redirect, could be useful on mobile device
# callback_uri = 'oob'
# 2) customer registered redirect url, could be useful on a mobile device
# callback_uri = 'janek:helloworld'
# 3) only interested in token and verifier, so the actual address doesn't really matter
callback_uri = 'http://127.0.0.1/callback'


# starting main part
print 'Starting...'


# list available credentials
print
print 'Selecting credentials...'
credentials = read_store(credentials_store_name, 'credentials')
if credentials is not None:
    index = 0
    for credential in credentials:
        index += 1
        print str(index) + ' : ' + credential.get('owner')
print 'a : Add a new set of credentials'
print 'q : Quit program'
choice = raw_input('Your choice?: ')

if choice == 'q':
    sys.exit()

chosen_credentials = {}
if choice == 'a':
    credentials = []
    print 'Adding credentials...'
    owner = raw_input('Owner: ')
    client_key = raw_input('Client key: ')
    client_secret = raw_input('Client secret: ')
    chosen_credentials = {"owner": owner, "client_key": client_key, "client_secret": client_secret}
    credentials.append(chosen_credentials)
    write_store(credentials_store_name, 'credentials', credentials)
else:
    chosen_credentials = credentials[int(choice) - 1]

print
print 'Selecting a token...'
tokens = read_store(token_store_name, 'tokens')
if tokens is None:
    tokens = {chosen_credentials.get('owner'): []}
owner_tokens = tokens.get(chosen_credentials.get('owner'))
if owner_tokens is not None:
    index = 0
    for token in owner_tokens:
        index += 1
        print str(index) + ' : ' + token.get('user') + ' (created: ' + token.get('timestamp') + ')'
print 'a : add a new token'
print 'q : quit program'
choice = raw_input('Your choice?: ')

if choice == 'q':
    sys.exit()

chosen_token = {}
client_key = chosen_credentials.get('client_key')
client_secret = chosen_credentials.get('client_secret')
if choice == 'a':
    print 'Adding a token...'

    print 'Step 0: access API catalog (using only client security context)'
    oauth_session = OAuth1Session(client_key, client_secret=client_secret)
    url = base_url + '/'
    r = oauth_session.get(url, headers=DEFAULT_JSON_HEADER)
    response = r.json()
    print json.dumps(response, indent=4, sort_keys=True)
    request_token_url = extract_link(response, 'oauthRequestToken')
    authorization_url = extract_link(response, 'oauthAuthorizeRequestToken')
    #authorization_url = 'https://my.deere.com/consentToUseOfData'
    access_token_url = extract_link(response, 'oauthAccessToken')
    wait = raw_input('Enter to continue...')

    print
    print 'Step 1: use urls from catalog to fetch a request token (using same client security context)'
    oauth_session = OAuth1Session(client_key, client_secret=client_secret, callback_uri=callback_uri)
    r = oauth_session.fetch_request_token(url=request_token_url)
    print json.dumps(r, indent=4, sort_keys=True)
    wait = raw_input('Enter to continue...')

    print
    print 'Step 2: follow this link to authorize (this requires action by the user)'
    authorization_url = authorization_url.replace("oauth_token={token}","")
    print oauth_session.authorization_url(authorization_url)
    redirect_url = raw_input('Paste full redirect url: ')

    print
    print 'Step 3: fetch access token'
    parsed_response = oauth_session.parse_authorization_response(redirect_url)
    print(json.dumps(parsed_response, indent=4, sort_keys=True))
    r = oauth_session.fetch_access_token(access_token_url)
    print 'Access token and secret:'
    print json.dumps(r, indent=4, sort_keys=True)
    token = r.get('oauth_token')
    token_secret = r.get('oauth_token_secret')
    wait = raw_input('Enter to continue...')

    r = oauth_session.get(base_url + '/', headers=DEFAULT_JSON_HEADER)
    currentUser_url = extract_link(r.json(), 'currentUser')
    r = oauth_session.get(currentUser_url, headers=DEFAULT_JSON_HEADER)
    user = r.json().get('accountName')
    chosen_token = {"user": user, "token": token, "token_secret": token_secret, "timestamp": str(datetime.now())}
    tokens[chosen_credentials.get('owner')].append(chosen_token)
    write_store(token_store_name, 'token', tokens)

else:
    chosen_token = owner_tokens[int(choice) - 1]
    oauth_session = OAuth1Session(client_key, client_secret=client_secret,
                                  resource_owner_key=chosen_token.get('token'),
                                  resource_owner_secret=chosen_token.get('token_secret'))

print
r = oauth_session.get(base_url + '/', headers=DEFAULT_JSON_HEADER)
prev_response = r.json()
print json.dumps(prev_response, indent=4, sort_keys=True)
while True:
    print
    print
    print 'u : upload a file'
    print 'd : download a file'
    print 'r : remove a file'
    print '  : enter any resource URI starting with \'/\''
    print '  : follow any relationship using the rel name'
    print 'q : quit program'
    choice = raw_input('Your choice?: ')

    try:
        if choice == 'q':
            break

        elif choice == 'u':
            local_path = raw_input('Local path?: ')
            mjd_name = raw_input('Name for upload?: ')

            # find right organization to upload the file to
            organizations_url = extract_link(oauth_session.get(base_url + '/',
                                                               headers=DEFAULT_JSON_HEADER).json(), 'organizations')
            organizations = oauth_session.get(organizations_url, headers=DEFAULT_JSON_HEADER).json().get('values')
            member_organizations = []
            if organizations is not None:
                for organization in organizations:
                    if organization.get('member'):
                        member_organizations.append({"id": organization.get('id'), "name": organization.get('name'),
                                                     "file_url": extract_link(organization, 'files')})

            # if user belongs to multiple organization, let him pick
            org_file_url = None
            if len(member_organizations) == 0:
                print 'It appears that \'' + chosen_token.get('user') + \
                      '\' doesn\'t have an account on MyJohnDeere, no (member) organizations found. ' \
                      'Not able to upload any files.'
            else:
                if len(member_organizations) > 1:
                    print 'Found multiple possible organizations for upload...'
                    index = 1
                    for member_organization in member_organizations:
                        print str(index) + ' : ' + member_organization.get('name')
                        index += 1
                    org_selection = raw_input('Which organization?: ')
                    org_file_url = member_organizations[int(org_selection) - 1].get('file_url')
                else:
                    org_file_url = member_organizations[0].get('file_url')

                # create meta data
                # body = '{ "file": {"-xmlns": "' + base_url + '/v3", "name": "' + mjd_name + '"}}'
                body = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' \
                       '<file xmlns="http://api.deere.com/v3">' \
                       '<name>' + mjd_name + '</name>' \
                                             '</file>'
                headers = {
                    'Accept': 'application/vnd.deere.axiom.v3+json',
                    'Content-Type': 'application/vnd.deere.axiom.v3+xml',
                    'Content-Length': len(body)
                }
                r = oauth_session.post(org_file_url, headers=headers, data=body)

                if r.status_code == 201:
                    # create file content
                    file_for_upload = open(local_path, 'rb')
                    upload_data = file_for_upload.read()
                    file_for_upload.close()
                    print 'Data size: ', len(upload_data)
                    headers = {'Accept': 'application/vnd.deere.axiom.v3+json',
                               'Content-Type': 'application/zip',
                               'Content-Length': len(upload_data)}
                    file_location_url = r.headers.get('location')
                    r = oauth_session.put(file_location_url, headers=headers, data=upload_data)
                    if 200 <= r.status_code < 300:
                        print 'File \'' + local_path + '\' successfully uploaded to \'' + mjd_name + '\'.'
                    else:
                        print 'Not able to upload file content for \'' + mjd_name + '\'.'
                else:
                    print 'Not able to create meta-data for file \'' + mjd_name + '\'.'
            prev_response = None

        elif choice == 'r':
            file_id = raw_input('File ID?: ')
            file_url = base_url + '/files/' + file_id
            r = oauth_session.get(file_url, headers=DEFAULT_JSON_HEADER)
            file_name = r.json().get('name')
            r = oauth_session.delete(file_url, headers=DEFAULT_JSON_HEADER)
            if 200 <= r.status_code < 300:
                print 'File \'' + file_name + '\' (' + file_id + ') successfully deleted.'
            else:
                print 'Not able to delete \'' + file_name + '\' (' + file_id + ').'
            prev_response = None

        elif choice == 'd':
            file_id = raw_input('File ID?: ')
            local_path = raw_input('Local path?: ')
            headers = {'Accept': 'application/zip'}
            r = oauth_session.get(base_url + '/files/' + file_id, headers=headers, stream=True)
            with open(local_path, 'wb') as fd:
                for chunk in r.iter_content():
                    fd.write(chunk)
            prev_response = None

        else:
            prev_response = handle_endpoint(choice, prev_response)

    except:
        prev_response = None
        print '>>> !!! Error occurred, try again !!! <<<'
        print sys.exc_info()

print
print 'Finished.'
print
