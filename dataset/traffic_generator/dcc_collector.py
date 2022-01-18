from __future__ import print_function
import os.path
import io
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/drive.readonly']

'''
*************************************************************************************************************
*************************************************************************************************************
Whenever collecting traffic using OWASP ZAP:

1) - export https_proxy='http://localhost:8080'
2) - make use of patched httplib2 and requests libraries - in order to deactivate SSL certificate validation
3) - ZAP can intercept max 10MB THEREFORE the traffic trace will just download a single 10MB file following a file listing, then leave it up to experiment to repeat+time accordingly
*************************************************************************************************************
*************************************************************************************************************
'''

def main():

    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())


    # Call the Drive v3 API - Quick test
    '''
    service = build('drive', 'v3', credentials=creds)
    results = service.files().list(
        pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
    else:
        print('Files:')
        for item in items:
            print(u'{0} ({1})'.format(item['name'], item['id']))
    '''

    drive = build('drive', 'v3', credentials=creds)
    # Call the Drive v3 API - List file_collection dir
    # First, get the folder ID by querying by mimeType and name
    folderId = drive.files().list(q="mimeType='application/vnd.google-apps.folder' and name = 'file_collection'", pageSize=10, fields="nextPageToken, files(id, name)").execute()
    # this gives us a list of all folders with that name
    folderIdResult = folderId.get('files', [])
    # however, we know there is only 1 folder with that name, so we just get the id of the 1st item in the list
    id = folderIdResult[0].get('id')
    # Now, using the folder ID gotten above, we get all the files from
    # that particular folder
    print("Folder id "+id)
    results = drive.files().list(q = "'" + id + "' in parents", pageSize=10, fields="nextPageToken, files(id, name)").execute()
    items = results.get('files', [])

    if not items:
        print('No files found.')
    else:
       #display
        print('Files:')
        for item in items:
            print(u'{0} ({1})'.format(item['name'], item['id']))
       #download
        for f in range(0, len(items)):
            fId = items[f].get('id')
            fName = items[f].get('name')
            print(fName, fId)
            fileRequest = drive.files().get_media(fileId=fId)
            fh = io.BytesIO()
            downloader = MediaIoBaseDownload(fh, fileRequest)
            done = False
            while done is False:
                status, done = downloader.next_chunk()
                print("Download %d%%." % int(status.progress() * 100))
            fh.seek(0)
            #fhContents = fh.read()
            with open("collected_evidence/"+fName, "wb") as outfile:
                    # Copy the BytesIO stream to the output file
                    outfile.write(fh.getbuffer())

if __name__ == '__main__':
    main()





