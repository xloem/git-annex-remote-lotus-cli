# This program is free software: you can redistribute it and/or modify it under the terms of version 3 of the GNU
# General Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#

import os, traceback, subprocess, sys, time
import json
from pathlib import Path
from dateutil.parser import isoparse


from . import __version__
from . import __name__ as MODULENAME
from annexremote import __version__ as annexremote_version
#from drivelib import __version__ as drivelib_version
from . import _default_client_id as DEFAULT_CLIENT_ID


#from drivelib import GoogleDrive
#from drivelib import Credentials
#from drivelib.errors import NumberOfChildrenExceededError

#from .keys import Key, NodirRemoteRoot, NestedRemoteRoot, LowerRemoteRoot, DirectoryRemoteRoot, MixedRemoteRoot
#from .keys import ExportRemoteRoot, ExportKey
#from .keys import HasSubdirError, NotAFileError, NotAuthenticatedError


#from oauth2client.client import OAuth2Credentials
#from google.auth.exceptions import RefreshError

#from googleapiclient.errors import HttpError
#from json.decoder import JSONDecodeError

from functools import wraps

#from tenacity import Retrying, retry
#from tenacity import retry_if_exception_type
#from tenacity import wait_exponential, wait_fixed
#from tenacity import stop_after_attempt

import annexremote
from annexremote import RemoteError
from annexremote import ProtocolError

from pathlib import Path
import logging

import humanfriendly

def NotAFolderError(Exception):
    pass

retry_conditions = {
        'wait': wait_exponential(multiplier=1, max=10),
        'retry': (
            retry_if_exception_type(HttpError) |
            retry_if_exception_type(ConnectionResetError)
        ),
        'stop': stop_after_attempt(5),
        'reraise': True,
    }
    
def send_version_on_error(f):
    @wraps(f)
    def send_version_wrapper(self, *args, **kwargs):
        try:
            return f(self, *args, **kwargs)
        except:
            self._send_version()
            raise

    return send_version_wrapper

def run(*params, input=None):
    proc = subprocess.run(params, capture_output = True, input = input)
    proc.check_returncode()
    return (proc.stdout.decode() + proc.stderr.decode()).strip()

class LotusCliRemote(annexremote.ExportRemote):

    def __init__(self, annex):
        super().__init__(annex)
        #self.DEFAULT_CHUNKSIZE = "32GiB"
        self.configs = {
            #'prefix': "The path to the folder that will be used for the remote."
            #            " If it doesn't exist, it will be created.",
            #'layout': "How the keys should be stored in the remote folder."
            #                 "Available options: `nested`(default), `nodir`, `lower` and `mixed`.",
            'miner': "Associated filecoin miner storing this data.",
            #'root_id': "Instead of the path, you can specify the ID of a folder."
            #            " The folder must already exist. This will make it independent"
            #            " from the path and it will always be found by git-annex, no matter"
            #            " where you move it. Can also be used to access shared folders"
            #            " which you haven't added to 'My Drive'."
            #            " Note: If both are given, `prefix` is preferred. You can unset"
            #            " `prefix` by setting it to the empty string ('prefix=\"\"').",
            #'transferchunk':
            #            "Chunksize used for transfers. This is the minimum data which"
            #            " has to be retransmitted when resuming after a connection error."
            #            " This also affects the progress display. It has to be distinguished"
            #            " from `chunk`. A value between 1MiB and 10MiB is recommended."
            #            " Smaller values meaning less data to be re-transmitted when network"
            #            " connectivity is interrupted and result in a finer progress feedback."
            #            " Bigger values create slightly less overhead and are therefore"
            #            " somewhat more efficient."
            #            " Default: {}".format(self.DEFAULT_CHUNKSIZE),
            #'mute-api-lockdown-warning':
            #            "Set to 'true' if you don't want to see the warning.",
            'verified': "Set to 'true' if you want to always use verified deals.",
            'from': "Specify non-default address to fund deals with.",
            'days': "How long the miner should store the data for in days. Usual range: 180 - 538",
            #'token':    "Token file that was created by `git-annex-remote-googledrive setup`",
            #'auto_fix_full':    "`yes` if the remote should try to fix full-folder issues"
            #                    " automatically. See https://github.com/Lykos153/git-annex-remote-googledrive#fix-full-folder",
        }

    #@property
    #def root(self):
    #    if not hasattr(self, '_root') or self._root is None: # pylint: disable=access-member-before-definition
    #        prefix = self.annex.getconfig('prefix')
    #        root_id = self.annex.getconfig('root_id')
    #        exporttree = self.annex.getconfig('exporttree')
    #        if exporttree == "yes":
    #            root_class = ExportRemoteRoot
    #        else:
    #            layout_mapping = {
    #                'nodir':    NodirRemoteRoot,
    #                'nested':   NestedRemoteRoot,
    #                'lower':    LowerRemoteRoot,
    #                #'directory': DirectoryRemoteRoot,
    #                'mixed':    MixedRemoteRoot,
    #            }
    #            root_class = layout_mapping.get(self.layout, None)
    #            if root_class is None:
    #                raise RemoteError("`layout` must be one of {}".format(list(layout_mapping.keys())))

    #        if self.credentials is None:
    #            raise RemoteError("Stored credentials are invalid. Please re-run `git-annex-remote-googledrive setup` and `git annex enableremote <remotename>`")

    #        try:
    #            if prefix:
    #                root = root_class.from_path(self.credentials, prefix, annex=self.annex, uuid=self.uuid, local_appdir=self.local_appdir)
    #            else:
    #                root = root_class.from_id(self.credentials, root_id, annex=self.annex, uuid=self.uuid, local_appdir=self.local_appdir)
    #        except JSONDecodeError:
    #            raise RemoteError("Access token invalid, please re-run `git-annex-remote-googledrive setup`")
    #        except (NotAuthenticatedError, RefreshError):
    #            raise RemoteError("Failed to authenticate with Google. Please run 'git-annex-remote-googledrive setup'.")
    #        except FileNotFoundError:
    #            if prefix:
    #                raise RemoteError("Prefix {} does not exist or does not point to a folder.".format(prefix))
    #            else:
    #                raise RemoteError("File ID {} does not exist or does not point to a folder.".format(root_id))

    #        if root.id != root_id and not (hasattr(self, 'isinitremote') and self.isinitremote is True):
    #            raise RemoteError("ID of root folder changed. Was the repo moved? Please check remote and re-run git annex enableremote")

    #        self.credentials = root.creds()
    #        
    #        self._root = root
    #    return self._root

    @property
    def encryption(self):
        if not hasattr(self, '_encryption'):
            self._encryption = self.annex.getconfig('encryption')
        return self._encryption

    @property
    def uuid(self):
        if not hasattr(self, '_uuid'):
            self._uuid = self.annex.getuuid()
        return self._uuid

    @property
    def miner(self):
        if not hasattr(self, '_miner'):
            self._miner = self.annex.getconfig('miner')
        return self._miner

    @property
    def from_addr(self):
        if not hasattr(self, '_from'):
            self._from = self.annex.getconfig('from')
        return self._from

    @property
    def duration(self):
        if not hasattr(self, '_duration'):
            days = self.annex.getconfig('days')
            if not days:
                #self._duration = 518400 # minimum, 180 days
                #self._duration = 1555200 # maximum, 540 days
                self._duration = 530 * 24 * 60 * 2 # 530 days
            else:
                self._duration = days * 24 * 60 * 2
        return self._duration

    #@property
    #def local_appdir(self):
    #    if not hasattr(self, '_local_appdir'):
    #        self._local_appdir = Path(self.annex.getgitdir()) / "annex/remote-googledrive"
    #    return self._local_appdir

    #@property
    #def layout(self):
    #    layout = self.annex.getconfig("layout")

    #    for import_layout_name in ["rclone_layout", "gdrive_layout"]:
    #        import_layout = self.annex.getconfig(import_layout_name)
    #        if import_layout and not layout:
    #            layout = import_layout
    #            self.annex.setconfig(import_layout_name, "")

    #    self.annex.setconfig("layout", layout)
    #    default_layout = "nodir"

    #    if not layout:
    #        layout = default_layout
    #        self.annex.info("No layout was specified. Defaulting to `nodir` for compatibility. This will change in v2.0.0.")

    #    return layout

    #@property
    #def info(self):
    #    return_dict = {}
    #    prefix = self.annex.getconfig("prefix")
    #    if prefix:
    #        return_dict['remote prefix'] = prefix
    #    else:
    #        return_dict['remote root-id'] = self.annex.getconfig("root_id")
    #    return_dict['remote layout'] = self.layout
    #    return_dict['transfer chunk size'] = humanfriendly.format_size(self.chunksize, binary=True)
    #    return return_dict

    #@info.setter
    #def info(self, info):
    #    pass
        
    #@property
    #def chunksize(self):
    #    if not hasattr(self, '_chunksize'):
    #        try:
    #            transferchunk = self.annex.getconfig('transferchunk')
    #            self._chunksize = humanfriendly.parse_size(transferchunk)
    #            self.annex.debug("Using chunksize: {}".format(transferchunk))
    #        except humanfriendly.InvalidSize:
    #            self.annex.debug("No valid chunksize specified. Using default value: {}".format(self.DEFAULT_CHUNKSIZE))
    #            self._chunksize = humanfriendly.parse_size(self.DEFAULT_CHUNKSIZE)
    #    return self._chunksize

    @property
    def verified(self):
        if not hasattr(self, '_verified'):
            self._verified = (self.annex.getconfig('verified') == 'true')
        return self._verified

    @property
    def ask(self):
        if not hasattr(self, '_ask'):
            lines = run('lotus', 'client', 'query-ask', self.miner).split('\n')
            values = [line.split(': ')[1] for line in lines]
            if len(values) != 5 or values[0] != self.miner:
                raise RemoteError('unexpected ask output', *lines)
            self._ask = {
                'ask': values[0],
                'unverified_price': values[1],
                'verified_price': values[2],
                'maxsize': humanfriendly.parse_size(values[3]),
                'minsize': humanfriendly.parse_size(values[4])
            }
        return self._ask

    @property
    def price_GiB(self):
        return self.ask['verified_price' if self.verified else 'unverified_price']

    @property
    def minsize(self):
        return self.ask['minsize']

    @property
    def maxsize(self):
        return self.ask['maxsize']

    #@property
    #def credentials(self):
    #    if not hasattr(self, '_credentials'):
    #        json_creds = self.annex.getcreds('credentials')['user']
    #        try:
    #            self._credentials = Credentials.from_json(json_creds)
    #        except json.decoder.JSONDecodeError:
    #            self.annex.debug("Error decoding stored credentials: {}".format(json_creds))
    #            self._credentials = None
    #    return self._credentials

    #@credentials.setter
    #def credentials(self, creds):
    #    if creds != self.credentials:
    #        self._credentials = creds
    #        self.annex.setcreds('credentials', ''.join(Credentials.to_json(creds).split()), '')

    @send_version_on_error
    def initremote(self):
        self.isinitremote = True
        self._send_version()
        miner = self.annex.getconfig('miner')
        #prefix = self.annex.getconfig('prefix')
        #root_id = self.annex.getconfig('root_id')
        #if not prefix and not root_id:
        #    raise RemoteError("Either prefix or root_id must be given.")
        if not miner:
            raise RemoteError("Miner must be given.")

        #token_config = self.annex.getconfig('token')
        #if token_config:
        #    self.annex.setconfig('token', "")
        #    token_file = Path(token_config)
        #else:
        #    git_root = Path(self.annex.getgitdir())
        #    othertmp_dir = git_root / "annex/othertmp"
        #    othertmp_dir.mkdir(parents=True, exist_ok=True)
        #    token_file = othertmp_dir / "git-annex-remote-googledrive.token"

        #try:
        #    self.credentials = Credentials.from_authorized_user_file(token_file)
        #except Exception as e:
        #    if token_config:
        #        raise RemoteError("Could not read token file {}:".format(token_file), e)
        #    self.annex.debug("Error reading token file at {}".format(token_file),
        #                     e,
        #                     " Trying embedded credentials")
        #    if not self.credentials:
        #        raise RemoteError("No Credentials found. Run 'git-annex-remote-googledrive setup' in order to authenticate.")

        #self.annex.setconfig('root_id', self.root.id)
        self.isinitremote = False

    def prepare(self):
        self._send_version()

        #if self.annex.getconfig('mute-api-lockdown-warning') != "true" and \
        #        self.credentials.client_id == DEFAULT_CLIENT_ID:

        #    self._info("====== git-annex-remote-googledrive")
        #    self._info("IMPORTANT: Google has started to lockdown their Google Drive API. This might affect access to your Google Drive remotes.")
        #    self._info("Please consider untrusting this remote until it is clear what happends next.")
        #    self._info("Read more on https://github.com/Lykos153/git-annex-remote-googledrive#google-drive-api-lockdown")
        #    self._info("You can mute this warning by issuing 'git annex enableremote <remote-name> mute-api-lockdown-warning=true'")
        #    self._info("======")

    @send_version_on_error
    @retry(**retry_conditions)
    def transfer_store(self, key, fpath):
        #fpath = Path(fpath)
        importnum, importcid = (item.split(' ')[1] for item in run('lotus', 'client', 'import', fpath).split(', '))
        logging.debug("Imported %s as %s %s", fpath, importnum, importcid)
        dealparams = ['lotus', 'client', 'deal']
        if self.verified:
            dealparams.append('--verified-deal')
        if self.from_addr:
            dealparams.extend(('--from', self.from_addr))
        dealparams.extend((cid, self.miner, self.price_per_GiB, self.duration))

        dealcid = run(*dealparams)
        self.seturipresent(key, 'filecoin://' + self.miner + '/' + dealcid + '/import/' + importnum)

        lastmsg = None
        lastlog = isoparse('0001-01-01T00:00:00Z')
        while True:
            getdeal = self._dealfromcid(dealcid, importnum)
            dealinfo = getdeal['DealInfo: ']
            if dealinfo['DealID']:
                break
            dealstages = dealinfo['DealStages']['Stages']
            dealstage = dealstages[-1]
            state = dealinfo['State']
            msg = dealinfo['Message']

            lastlastlog = lastlog
            for stage in dealstages:
                createdtime = isoparse(stage['CreatedTime'])
                if createdtime > lastlog:
                    self._info(stage['Name'] + ' ' + stage['Description'])
                    lastlog = createdtime

                updatedtime = isoparse(stage['UpdatedTime'])
                if updatedtime > lastlog:
                    for log  in stage['Logs']:
                        updatedtime = isoparse(stage['UpdatedTime'])
                        if updatedtime > lastlog:
                            self._info(log['Log'])
                            lastlog = updatedtime

            if state == 26: # StorageDealError
                run('lotus', 'client', 'drop', importnum)
                self.seturimissing(key, 'filecoin://' + self.miner + '/' + dealcid + '/import/' + importnum)
                raise RemoteError(msg)

            if lastlog == lastlastlog:
                time.sleep(60)

            # the transfer info is actually in the getdeal output, look at a completed deal to see

    @send_version_on_error
    def claimurl(self, url):
        proto = 'filecoin://' + self.miner + '/'
        protolen = len(proto)
        return len(url) > protolen and url[:protolen] == proto

    @send_version_on_error
    @retry(**retry_conditions)
    def transfer_retrieve(self, key, fpath):
        # can also retrieve from local
        for url in self.geturls(key, 'filecoin://' + self.miner + '/onchain/':
            dealcid, state, id = url.split('/')[3:]
            deal = json.loads(run('lotus', 'state', 'get-deal', id))
            proposal = deal['Proposal']
            label = proposal['Label']

            retrparams = ['lotus', 'client', 'retrieve']
            if self.from_addr:
                retrparams.extend(('--from', self.from_addr))
            retrparams.extend(('--miner', self.miner, label, fpath))

            for line in run(*retrparams).split('\n'):
                self._info(line)
    
    @send_version_on_error
    @retry(**retry_conditions)
    def checkpresent(self, key):
        results = []
        for url in self.geturls(key, 'filecoin://' + self.miner + '/':
            dealcid, state, id = url.split('/')[3:]
            if state == 'onchain':
                try:
                    deal = json.loads(run('lotus', 'state', 'get-deal', id))
                except subprocess.CalledProcessError as err:
                    self._info(err.stdout.decode())
                    self._info(err.stderr.decode())
                    #self.seturimissing('deal') should be url not 'deal'
                    continue
                proposal = deal['Proposal']
                provider = proposal['Provider']
                if provider != self.miner:
                    continue
                startepoch = proposal['StartEpoch']
                endepoch = proposal['EndEpoch']
                epoch = run('lotus', 'chain', 'list', '--count', 1).split(':')[0]
                epoch = int(epoch)
                if (startepoch + endepoch) / 2 > epoch:
                    results.append({
                        'url': url,
                        'size': proposal['PieceSize'],
                        'filename': proposal['Label']
                    })
            elif state == 'import':
                deal = self._dealfromcid(dealcid, id)
                dealinfo = deal['DealInfo: ']
                if dealinfo['DealID'] and dealinfo['Provider'] == self.miner:
                    results.append({
                        'url': url,
                        'size': deal['OnChain']['Proposal']['PieceSize']
                    })
        return results

    def _dealfromcid(self, dealcid, importnum):
        deal = json.loads(run(('lotus', 'client', 'get-deal', dealcid)))
        dealinfo = deal['DealInfo: ']
        if dealinfo['DealID']:
            dealid = dealinfo['DealID']
            provider = dealinfo['Provider']
            #label = getdeal['OnChain']['Proposal']['Label']
            self.seturipresent(key, 'filecoin://' + provider + '/' + dealcid + '/onchain/' + dealid)
            try:
                run('lotus', 'client', 'drop', importnum)
            except:
                pass
            self.seturimissing(key, 'filecoin://' + provider + '/' + dealcid + '/import/' + importnum)
        return deal


    #@send_version_on_error
    #@retry(**retry_conditions)
    #def remove(self, key):
    #    self.root.delete_key(key)

    #@send_version_on_error
    #@retry(**retry_conditions)
    #def transferexport_store(self, key, fpath, name):
    #    #TODO: if file already exists, compare md5sum
    #    self.root.new_key(key, name).upload(
    #            fpath,
    #            chunksize=self.chunksize,
    #            progress_handler=self.annex.progress
    #    )

    #@send_version_on_error
    #@retry(**retry_conditions)
    #def transferexport_retrieve(self, key, fpath, name):
    #    self.root.get_key(key, name).download(
    #        fpath,
    #        chunksize=self.chunksize,
    #        progress_handler=self.annex.progress
    #    )

    #@send_version_on_error
    #@retry(**retry_conditions)
    #def checkpresentexport(self, key, name):
    #    try:
    #        self.root.get_key(key, name)
    #        return True
    #    except FileNotFoundError:
    #        return False

    #@send_version_on_error
    #@retry(**retry_conditions)
    #def removeexport(self, key, name):
    #    self.root.delete_key(key, name)

    #@send_version_on_error
    #@retry(**retry_conditions)
    #def removeexportdirectory(self, directory):
    #    try:
    #        self.root.delete_dir(directory)
    #    except NotADirectoryError:
    #        raise RemoteError("{} is a file. Not deleting".format(directory))

    #@send_version_on_error
    #@retry(**retry_conditions)
    #def renameexport(self, key, name, new_name):
    #    self.root.rename_key(key, name, new_name)
    #        
    #def _splitpath(self, filename):
    #    splitpath = filename.rsplit('/', 1)
    #    exportfile = dict()
    #    if len(splitpath) == 2:
    #        exportfile['path'] = splitpath[0]
    #        exportfile['filename'] = splitpath[1]
    #    else:
    #        exportfile['path'] = ''
    #        exportfile['filename'] = splitpath[0]
    #    return exportfile
            
    def _send_version(self):
        global __version__
        global annexremote_version
        global drivelib_version
        self.annex.debug("Running {} version {}".format(
                            MODULENAME,
                            __version__
                        ))
        self.annex.debug("Using AnnexRemote version", annexremote_version)
        self.annex.debug("Using Drivelib version", drivelib_version)
    
    def _info(self, message):
        try:
            self.annex.info(message)
        except ProtocolError:
            print(message, file=sys.stderr)
