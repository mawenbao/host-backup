#!/usr/bin/env python
# -*- coding: utf-8 -*-
# host backup/restore script
# date: 2012.10.26 - 2012.12.07
# author: wilbur.ma@hotmail.com
# require:
#     python2.6 or python2.7
#     aes.py      - aes encryption
#     gnu tar     - archive
#     mutt        - send mail
#     mysql       - mysql database backup
#     dropbox sdk - required for dropbox backup
# history:
#     0.0.3    2012.11.27    add dropbox support
#     0.0.2    2012.11.02    add email support
#     0.0.1    2012.10.26    first release
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
# SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
# FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.

import os, sys, time, getpass, ConfigParser, optparse, commands, binascii, tempfile
import aes
# cmd options
parser = optparse.OptionParser()
parser.add_option("-c", "--config", dest="config", default="backup-config.ini", help="Path of the config file.")
parser.add_option("-b", "--backup", dest="backup", action="store_true", help="Backup mode")
parser.add_option("-r", "--restore", dest="restore", action="store_true", help="Restore mode")
parser.add_option("-f", "--file", dest="file", default="host-backup.tar.bz2", help="Path of the backup archive.")
(options, args) = parser.parse_args()

# backup variables
emptyStr = "0"

backupWithEmail = 0
backupWithDropbox = 0
dropboxAccessToken = emptyStr
sepChar = ":"
dateFormat = "%Y%m%d%H%M%S"
defaultDateFormat = "%Y-%m-%d %H:%M:%S"
removeExistFirst = 1
excludeVCS = 0
excludePattern = 0
fileList = []
dbList = []
tmpDir = tempfile.mkdtemp(prefix="host-backup-")

# check and extract backup archive
if options.restore:
    if not os.path.exists(options.file):
        print("archive file not exists, program exits.")
        sys.exit()
    print("Extract host backup file...")
    os.system("tar -C %s -xpf %s" % (tmpDir, options.file))

# parse config file
GeneralSection = "General"
FileListSection = "FileList"
OwnerListSection = "OwnerList"
MysqlSection = "DB.Mysql"
EmailSection = "Email"
BackupSection = "Backup"
DropboxSection = "Dropbox"
GitRepoSection = "Repo.Git"

configParser = ConfigParser.RawConfigParser()
options.config = os.path.abspath(options.config)
if not os.path.exists(options.config):
    print("Configuration file not exists: %s, program exits." % (options.config))
configParser.read(options.config)
removeExistFirst = configParser.get(GeneralSection, "Remove_Exist_First")
removeAfterBackup = configParser.get(GeneralSection, "Remove_After_Backup")
dateFormat = configParser.get(GeneralSection, "Date_Format")
excludeVCS = configParser.get(GeneralSection, "Exclude_VCS")
excludePattern = configParser.get(GeneralSection, "Exclude_Pattern")
backupWithEmail = configParser.get(BackupSection, "with_email")
backupWithDropbox = configParser.get(BackupSection, "with_dropbox")

# get file list
fileListNames = configParser.options(FileListSection)
for fln in fileListNames:
    currListStr = configParser.get(FileListSection, fln)
    if currListStr != emptyStr:
        fileList.extend(currListStr.split(sepChar))
# get relative path to root
fileList = map(lambda x : x[1:], fileList)
# get db list
dbListStr = configParser.get(MysqlSection, "DB_List")
if dbListStr != emptyStr:
    dbList.extend(dbListStr.split(":"))

# get database auth info
dbUser = configParser.get(MysqlSection, "User")
if dbUser:
    dbUser = dbUser.strip()
dbPassStr = configParser.get(MysqlSection, "Password")
if dbPassStr:
    dbPassStr = dbPassStr.strip()

if dbList:
    if not dbUser or dbUser == emptyStr:
        dbUser = raw_input("Your user name for mysql: ")
        configParser.set(MysqlSection, "User", dbUser)
        dbPassStr = ""
    if not dbPassStr or dbPassStr == emptyStr:
        dbPass = getpass.getpass("Your password for mysql user %s: " % (dbUser))
        dbPassKey = aes.generateRandomKey(16)
        # set password with aes encryption
        tmpPass = aes.encryptData(dbPassKey, dbPass)
        configParser.set(MysqlSection, "Password", tmpPass.encode("hex") + sepChar + dbPassKey.encode("hex"))
    else:
        dbPass, dbPassKey = dbPassStr.split(":")
        dbPass = aes.decryptData(binascii.unhexlify(dbPassKey), binascii.unhexlify(dbPass))
    # verify mysql user and password
    ret = commands.getstatusoutput("mysqlshow -u%s -p%s" % (dbUser, dbPass))[0]
    if ret != 0:
        print("Wrong name or password for mysql user %s, program exits." % (dbUser))
        sys.exit()

# archive name of backup files
currTime = time.strftime(dateFormat, time.localtime())
plainTime = time.strftime(defaultDateFormat, time.localtime())
allBackupArchive = "host-backup-%s.tar" % (currTime)
filesBackupArchive = "%s/host-files-backup-%s.tar.bz2" % (tmpDir, currTime)
dbBackupArchive = "%s/host-db-backup-%s.tar.bz2" % (tmpDir, currTime)
repoBackupArchive = "%s/host-repo-backup-%s.tar.bz2" % (tmpDir, currTime)
configFile = os.path.basename(options.config)
configFileAbs = os.path.abspath(configFile)

if options.backup:
    # backup db
    print("Backup db...")
    if dbList:
        dbBackupFiles = ""
        for db in dbList:
            dbBackupFiles += (db + ".sql ")
            print("Backup db %s..." % (db))
            backupCmd = "mysqldump -uroot -p%s -B %s > %s/%s.sql" % (dbPass, db, tmpDir, db)
            os.system(backupCmd)
        os.system("tar -C %s -cjf %s %s" % (tmpDir, dbBackupArchive, dbBackupFiles))
    else:
        print("No databases need to be backed up")
    # backup files in fileList
    print("Backup files...")
    if fileList:
        arcCmd = "tar -C /"
        if excludeVCS and excludeVCS != emptyStr:
            arcCmd += " --exclude-vcs"
        if excludePattern and excludePattern != emptyStr:
            arcCmd += " --exclude=%s" % (excludePattern.strip().replace(":", " --exclude="))
        os.system("%s -cjhf %s %s" % (arcCmd, filesBackupArchive, " ".join(fileList)))
    else:
        print("No files need to be backed up")
    # backup code repository
    print("Backup code repository...")
    # check git
    ret = commands.getstatusoutput("git --help")[0]
    if ret != 0:
        print("Git not found. Please install git with `apt-get install' git first." )
    else:
        repoRoot = configParser.get(GitRepoSection, "root_dir")
        if repoRoot and repoRoot != emptyStr:
            if not os.path.exists(repoRoot):
                print("Repository root directory not exists: %s" % repoRoot)
            else:
                repoRoot = os.path.abspath(repoRoot)
                repoDirs = os.listdir(repoRoot)
                currDirAbs = os.path.abspath(os.curdir)
                repoBackupFiles = ""
                os.chdir(repoRoot)
                for rd in repoDirs:
                    os.chdir(os.path.join(repoRoot, rd))
                    print("Backup repository %s/%s..." % (repoRoot, rd))
                    os.system("git bundle create %s/%s.bundle --all" % (tmpDir, rd))
                    repoBackupFiles += ("%s.bundle " % rd)
                # return to previous directory
                os.chdir(currDirAbs)
                # archive git bundles
                os.system("tar -C %s -cjf %s %s" % (tmpDir, repoBackupArchive, repoBackupFiles))
    # archive all backup files including the config file
    allBackupFiles = ""
    if os.path.exists(dbBackupArchive):
        allBackupFiles += (" " + os.path.basename(dbBackupArchive))
    if os.path.exists(filesBackupArchive):
        allBackupFiles += (" " + os.path.basename(filesBackupArchive))
    if os.path.exists(repoBackupArchive):
        allBackupFiles += (" " + os.path.basename(repoBackupArchive))

    print("Archive all backup files to %s..." % (allBackupArchive))
    os.system("tar -C %s -cf %s %s" % (tmpDir, allBackupArchive, allBackupFiles))
    # send backup file via email
    mailList = configParser.get(EmailSection, "Mail_List")
    if backupWithEmail != emptyStr and mailList != emptyStr:
        # check mutt existence
        ret = commands.getstatusoutput("mutt --help")[0]
        if ret != 0:
            print("Mutt not found. Please install mutt with `apt-get install' mutt first." )
        else:
            print("Send backup archive via email...")
            ret, hostname = commands.getstatusoutput("hostname")
            if ret != 0:
                hostname = "unknown host"
            mailSubject = "host backup on %s from %s" % (plainTime, hostname)
            mailContent = mailSubject
            muttCmd = "echo '%s' | mutt -a '%s' -s '%s' -- %s" % (mailContent, allBackupArchive, mailSubject, mailList.replace(":", " "))
            os.system(muttCmd)
    # send backup file to dropbox
    dropboxAccessToken = configParser.get(DropboxSection, "access_token")
    if backupWithDropbox != emptyStr and backupWithDropbox:
        # get dropbox auth info
        dropboxUser = configParser.get(DropboxSection, "User")
        if dropboxUser:
            dropboxUser = dropboxUser.strip()
        dropboxPassStr = configParser.get(DropboxSection, "Password")
        if dropboxPassStr:
            dropboxPassStr = dropboxPassStr.strip()
        if not dropboxUser or emptyStr == dropboxUser:
            dropboxUser = raw_input("Your user name for dropbox: ")
            configParser.set(DropboxSection, "User", dropboxUser)
            dropboxPassStr = ""
        if not dropboxPassStr or dropboxPassStr == emptyStr:
            dropboxPassStr = getpass.getpass("Your password for dropbox user %s: " % (dropboxUser))
            dropboxPassKey = aes.generateRandomKey(16)
            # set password with aes encryption
            tmpPass = aes.encryptData(dropboxPassKey, dropboxPassStr)
            configParser.set(DropboxSection, "Password", tmpPass.encode("hex") + sepChar + dropboxPassKey.encode("hex"))
            # reset access token when username or password changes
            dropboxAccessToken = emptyStr
        else:
            dropboxPass, dropboxPassKey = dropboxPassStr.split(":")
            dropboxPass = aes.decryptData(binascii.unhexlify(dropboxPassKey), binascii.unhexlify(dropboxPass))
        # verify dropbox user and password
        appKey = configParser.get(DropboxSection, "APP_KEY")
        appSecret = configParser.get(DropboxSection, "APP_SECRET")
        accessType = "dropbox"
        print("Login to dropbox...")
        try:
            try:
                from dropbox import client, rest, session
            except ImportError, e:
                print("Dropbox sdk not found, please download and install the \
                latest dropbox sdk from https://www.dropbox.com/developers/reference/sdk")
                raise e
            sess = session.DropboxSession(appKey, appSecret, accessType)
            if dropboxAccessToken == emptyStr or not dropboxAccessToken:
                requestToken = sess.obtain_request_token()
                url = sess.build_authorize_url(requestToken)
                # Make the user sign in and authorize this token
                print("url: %s" % url)
                print("Please visit this website and press the 'Allow' button, then hit 'Enter' here.")
                raw_input()
                accessToken = sess.obtain_access_token(requestToken)
                # encrypt access token
                dropboxAccessTokenAesKey = aes.generateRandomKey(16)
                accessTokenKey = aes.encryptData(dropboxAccessTokenAesKey, accessToken.key)
                accessTokenSecret = aes.encryptData(dropboxAccessTokenAesKey, accessToken.secret)
                configParser.set(
                    DropboxSection,
                    "access_token",
                    "%s:%s:%s" % (accessTokenKey.encode("hex"), accessTokenSecret.encode("hex"), dropboxAccessTokenAesKey.encode("hex")))
                client = client.DropboxClient(sess)
            else:
                # read access token
                accessTokenStr = configParser.get(DropboxSection, "access_token")
                if not accessTokenStr or accessTokenStr == emptyStr:
                    raise Exception("Cannot read access_token in config file %s" % configFileAbs)
                accessTokenKey, accessTokenSecret, dropboxAccessTokenAesKey = accessTokenStr.split(":")
                accessTokenKey = aes.decryptData(binascii.unhexlify(dropboxAccessTokenAesKey), binascii.unhexlify(accessTokenKey))
                accessTokenSecret = aes.decryptData(binascii.unhexlify(dropboxAccessTokenAesKey), binascii.unhexlify(accessTokenSecret))
                sess.set_token(accessTokenKey, accessTokenSecret)
                # init client
                client = client.DropboxClient(sess)
            # send backup file
            dropboxBackupDir = configParser.get(DropboxSection, "target_dir")
            if not dropboxBackupDir:
                dropboxBackupDir = "/"
            else:
                dropboxBackupDir = dropboxBackupDir.rstrip("/")
            with open(allBackupArchive) as f:
                print("Upload %s to dropbox..." % (allBackupArchive))
                response = client.put_file("%s/%s" % (dropboxBackupDir, os.path.basename(allBackupArchive)), f)
        except Exception, e:
            print("Cannot upload backup file to dropbox: %s" % (e))

elif options.restore:
    # restore db
    print("Restore db...")
    sqlFilesTmp = "sql-tmp"
    if os.path.exists(sqlFilesTmp):
        os.system("rm -Rf %s" % (sqlFilesTmp))
    os.mkdir(sqlFilesTmp)
    os.system("tar -C %s -xpf host-db-backup-*.tar.bz2" % (sqlFilesTmp))
    dbList = os.listdir(sqlFilesTmp)
    for db in dbList:
        print("Restore db %s..." % (os.path.splitext(db)[0]))
        os.system("mysql -uroot -p%s < %s/%s" % (dbPass, sqlFilesTmp, db))
    os.system("rm -Rf %s" % (sqlFilesTmp))

    # restore files
    print("Restore files...")
    # remove existing files first if set
    if removeExistFirst and removeExistFirst != emptyStr:
        os.system("rm -Rf %s" % (" ".join(fileList)))
    os.system("tar -C / -xpf host-files-backup-*.tar.bz2")
    # change owner of files if set
    for fln in fileListNames:
        currListStr = configParser.get(FileListSection, fln)
        if configParser.has_option(OwnerListSection, fln):
            os.system("chown -R %s %s" % (configParser.get(OwnerListSection, fln), currListStr.replace(sepChar, " ")))

# remove backup file
if options.backup and removeAfterBackup and removeAfterBackup != emptyStr:
    os.system("rm -f %s" % (allBackupArchive))
    if options.config != configFileAbs:
        os.system("rm -f %s" % (configFileAbs))
# remove tmp files
print("Remove temp files...")
os.system("rm -Rf %s" % tmpDir)
# update config file
with open(options.config, "w") as f:
    configParser.write(f)
print("Task finished")

