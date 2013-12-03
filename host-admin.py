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
#     0.1      2013.12.02    refactor code structure
#     0.0.4    2013.11.11    send error outputs via email
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

import os, sys, time, getpass, ConfigParser, optparse, commands, binascii, tempfile, subprocess
import aes

# python2 ConfigParser do not accept empty ini value, so I use 0 instead
gEmptyStr = "0"
gTmpDir = tempfile.mkdtemp(prefix="host-backup-")
gDateFormat = "%Y%m%d%H%M%S"
gDefaultDateFormat = "%Y-%m-%d %H:%M:%S"
gSepChar = ":"
# store error output when doing the backup
gBackupErrorMsg = ""

# config class
class BackupConfig(object):
    def __init__(self, configPath):
        self.configPath = configPath

        self.backupWithEmail = 0
        self.backupWithDropbox = 0
        self.dropboxAccessToken = gEmptyStr
        self.removeExistFirst = 1
        self.excludeVCS = 0
        self.fileList = []
        self.dbList = []

    def _init_config_structure(self):
        self.GeneralSection = "General"
        self.FileListSection = "FileList"
        self.OwnerListSection = "OwnerList"
        self.MysqlSection = "DB.Mysql"
        self.EmailSection = "Email"
        self.BackupSection = "Backup"
        self.DropboxSection = "Dropbox"
        self.GitRepoSection = "Repo.Git"

    def parse(self):
        if not os.path.exists(self.configPath):
            print("Config file %s does not exist" % self.configPath)
            return False

        self._init_config_structure()
        self.configParser = ConfigParser.RawConfigParser()
        self.configParser.read(self.configPath)

        self._parse_file_list()
        self._parse_db_info()
        self._parse_misc()
        self._parse_repos()
        self._parse_dropbox()

        self._verify_db_pass()
        return True

    # update config file
    def update(self):
        with open(self.configPath, "w") as f:
            self.configParser.write(f)

    def _parse_misc(self):
        self.removeExistFirst = self.configParser.get(self.GeneralSection, "Remove_Exist_First")
        self.removeAfterBackup = self.configParser.get(self.GeneralSection, "Remove_After_Backup")
        self.dateFormat = self.configParser.get(self.GeneralSection, "Date_Format")
        self.excludeVCS = self.configParser.get(self.GeneralSection, "Exclude_VCS")
        self.excludePattern = self.configParser.get(self.GeneralSection, "Exclude_Pattern")
        self.backupWithEmail = self.configParser.get(self.BackupSection, "with_email")
        self.mailList = self.configParser.get(self.EmailSection, "Mail_List")
        self.backupWithDropbox = self.configParser.get(self.BackupSection, "with_dropbox")

    # get backup file list from config file
    def _parse_file_list(self):
        fileListNames = self.configParser.options(self.FileListSection)
        for fln in fileListNames:
            currListStr = self.configParser.get(self.FileListSection, fln)
            if currListStr != gEmptyStr:
                self.fileList.extend(currListStr.split(gSepChar))
        # get relative path to root
        self.fileList = map(lambda x : x[1:], self.fileList)

    def _parse_db_info(self):
        # get db list
        dbListStr = self.configParser.get(self.MysqlSection, "DB_List")
        if dbListStr != gEmptyStr:
            self.dbList.extend(dbListStr.split(":"))

        # get database auth info
        self.dbUser = self.configParser.get(self.MysqlSection, "User")
        if self.dbUser:
            self.dbUser = self.dbUser.strip()
        self.dbPassStr = self.configParser.get(self.MysqlSection, "Password")
        if self.dbPassStr:
            self.dbPassStr = self.dbPassStr.strip()

    def _parse_repos(self):
        # git repo
        self.repoRoot = self.configParser.get(self.GitRepoSection, "root_dir")
        if self.repoRoot and self.repoRoot != gEmptyStr:
            if not os.path.exists(self.repoRoot):
                print("Repository root directory does not exist: %s" % self.repoRoot)
            else:
                self.repoRoot = os.path.abspath(self.repoRoot)

    def _parse_dropbox(self):
        self.dropboxAccessToken = self.configParser.get(self.DropboxSection, "access_token")
        if self.backupWithDropbox != gEmptyStr and self.backupWithDropbox:
            # get dropbox auth info
            self.dropboxUser = self.configParser.get(self.DropboxSection, "User")
            if self.dropboxUser:
                self.dropboxUser = self.dropboxUser.strip()
            self.dropboxPassStr = self.configParser.get(self.DropboxSection, "Password")
            if self.dropboxPassStr:
                self.dropboxPassStr = self.dropboxPassStr.strip()
            if not self.dropboxUser or gEmptyStr == self.dropboxUser:
                self.dropboxUser = raw_input("Your user name for dropbox: ")
                self.configParser.set(self.DropboxSection, "User", self.dropboxUser)
                self.dropboxPassStr = ""
            if not self.dropboxPassStr or self.dropboxPassStr == gEmptyStr:
                self.dropboxPassStr = getpass.getpass("Your password for dropbox user %s: " % (self.dropboxUser))
                self.dropboxPassKey = aes.generateRandomKey(16)
                # set password with aes encryption
                tmpPass = aes.encryptData(dropboxPassKey, dropboxPassStr)
                self.configParser.set(self.DropboxSection, "Password", tmpPass.encode("hex") + gSepChar + self.dropboxPassKey.encode("hex"))
                # reset access token when username or password changes
                self.dropboxAccessToken = gEmptyStr
            else:
                self.dropboxPass, self.dropboxPassKey = self.dropboxPassStr.split(":")
                self.dropboxPass = aes.decryptData(binascii.unhexlify(self.dropboxPassKey), binascii.unhexlify(self.dropboxPass))
        self.dropboxAppKey = self.configParser.get(self.DropboxSection, "APP_KEY")
        self.dropboxAppSecret = self.configParser.get(self.DropboxSection, "APP_SECRET")
        self.dropboxAccessType = "dropbox"
        self.dropboxBackupDir = self.configParser.get(self.DropboxSection, "target_dir")
        if not self.dropboxBackupDir:
            self.dropboxBackupDir = "/"
        else:
            self.dropboxBackupDir = self.dropboxBackupDir.rstrip("/")

    def _verify_db_pass(self):
        if not self.dbList:
            return False

        if not self.dbUser or self.dbUser == gEmptyStr:
            self.dbUser = raw_input("Your user name for mysql: ")
            self.configParser.set(MysqlSection, "User", dbUser)
            self.dbPassStr = ""
        if not self.dbPassStr or self.dbPassStr == gEmptyStr:
            dbPass = getpass.getpass("Your password for mysql user %s: " % (dbUser))
            dbPassKey = aes.generateRandomKey(16)
            # set password with aes encryption
            tmpPass = aes.encryptData(dbPassKey, dbPass)
            self.configParser.set(self.MysqlSection, "Password", tmpPass.encode("hex") + gSepChar + dbPassKey.encode("hex"))
        else:
            self.dbPass, self.dbPassKey = self.dbPassStr.split(":")
            self.dbPass = aes.decryptData(binascii.unhexlify(self.dbPassKey), binascii.unhexlify(self.dbPass))
        # verify mysql user and password
        ret = commands.getstatusoutput("mysqlshow -u%s -p%s" % (self.dbUser, self.dbPass))[0]
        if ret != 0:
            print("Wrong name or password for mysql user %s, program exits." % (self.dbUser))
            return False

        return True

# helper function that run a cmd and return (stdout, stderr)
def run_cmd(cmdStr):
    cmdList = cmdStr.split()
    proc = subprocess.Popen(cmdList, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()
    if stderr:
        stderr = "[ERROR] %s:\n%s" % (cmdList[0], stderr)
    return stdout, stderr

def parse_cmd_options():
    # cmd options
    parser = optparse.OptionParser()
    parser.add_option("-c", "--config", dest="config", default="backup-config.ini", help="Path of the config file.")
    parser.add_option("-b", "--backup", dest="backup", action="store_true", help="Backup mode")
    #parser.add_option("-r", "--restore", dest="restore", action="store_true", help="Restore mode")
    parser.add_option("-f", "--file", dest="file", default="host-backup.tar.bz2", help="Path of the backup archive.")
    (options, args) = parser.parse_args()
    return options, args

def backup_db(backupConfig, dbBackupArchive):
    global gBackupErrorMsg, gTmpDir
    # backup db
    print("Backup db...")
    if backupConfig.dbList:
        dbBackupFiles = ""
        for db in backupConfig.dbList:
            dbBackupFiles += (db + ".sql ")
            print("Backup db %s..." % (db))
            backupCmd = "mysqldump -uroot -p%s -B %s" % (backupConfig.dbPass, db)
            dbSqlContent, dbDumpError = run_cmd(backupCmd)
            gBackupErrorMsg += dbDumpError
            with open("%s/%s.sql" % (gTmpDir, db), "w") as f:
                f.write(dbSqlContent)
        gBackupErrorMsg += run_cmd("tar -C %s -cjf %s %s" % (gTmpDir, dbBackupArchive, dbBackupFiles))[1]
    else:
        print("No databases need to be backed up")

# backup files in fileList
def backup_files(backupConfig, tempFilesArchive):
    global gBackupErrorMsg
    print("Backup files...")
    if backupConfig.fileList:
        arcCmd = "tar -C /"
        if backupConfig.excludeVCS and backupConfig.excludeVCS != gEmptyStr:
            arcCmd += " --exclude-vcs"
        if backupConfig.excludePattern and backupConfig.excludePattern != gEmptyStr:
            arcCmd += " --exclude=%s" % (backupConfig.excludePattern.strip().replace(":", " --exclude="))
        gBackupErrorMsg += run_cmd("%s -cjhf %s %s" % (arcCmd, tempFilesArchive, " ".join(backupConfig.fileList)))[1]
    else:
        print("No files need to be backed up")

def backup_repos(backupConfig, backupArchive):
    global gBackupErrorMsg, gTmpDir
    # backup code repository
    print("Backup code repository...")
    repoDirs = os.listdir(backupConfig.repoRoot)
    currDirAbs = os.path.abspath(os.curdir)
    repoBackupFiles = ""
    os.chdir(backupConfig.repoRoot)
    for rd in repoDirs:
        os.chdir(os.path.join(backupConfig.repoRoot, rd))
        print("Backup repository %s/%s..." % (backupConfig.repoRoot, rd))
        gBackupErrorMsg += run_cmd("git bundle create %s/%s.bundle --all" % (gTmpDir, rd))[1]
        repoBackupFiles += ("%s.bundle " % rd)
    # return to previous directory
    os.chdir(currDirAbs)
    # archive git bundles
    gBackupErrorMsg += run_cmd("tar -C %s -cjf %s %s" % (gTmpDir, backupArchive, repoBackupFiles))[1]

# send backup file to dropbox
def upload_to_dropbox(backupConfig, backupArchive):
    print("Login to dropbox...")
    try:
        try:
            from dropbox import client, rest, session
        except ImportError, e:
            print("Dropbox sdk not found, please download and install the \
            latest dropbox sdk from https://www.dropbox.com/developers/reference/sdk")
            raise e
        sess = session.DropboxSession(backupConfig.dropboxAppKey, backupConfig.dropboxAppSecret, backupConfig.dropboxAccessType)
        if backupConfig.dropboxAccessToken == gEmptyStr or not backupConfig.dropboxAccessToken:
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
            backupConfig.configParser.set(
                backupConfig.DropboxSection,
                "access_token",
                "%s:%s:%s" % (accessTokenKey.encode("hex"), accessTokenSecret.encode("hex"), dropboxAccessTokenAesKey.encode("hex")))
            client = client.DropboxClient(sess)
        else:
            # read access token
            if not backupConfig.dropboxAccessToken or backupConfig.dropboxAccessToken == gEmptyStr:
                raise Exception("Cannot read access_token in config file %s" % backupConfig.configPath)
            accessTokenKey, accessTokenSecret, dropboxAccessTokenAesKey = backupConfig.dropboxAccessToken.split(":")
            accessTokenKey = aes.decryptData(binascii.unhexlify(dropboxAccessTokenAesKey), binascii.unhexlify(accessTokenKey))
            accessTokenSecret = aes.decryptData(binascii.unhexlify(dropboxAccessTokenAesKey), binascii.unhexlify(accessTokenSecret))
            sess.set_token(accessTokenKey, accessTokenSecret)
            # init client
            client = client.DropboxClient(sess)
        # send backup file
        with open(backupArchive) as f:
            print("Upload %s to dropbox..." % (backupArchive))
            response = client.put_file("%s/%s" % (backupConfig.dropboxBackupDir, os.path.basename(allBackupArchive)), f)
    except Exception, e:
        print("Cannot upload backup file to dropbox: %s" % (e))

def send_via_email(backupConfig, backupArchive):
    global gBackupErrorMsg
    # send backup file via email
    if backupConfig.backupWithEmail != gEmptyStr and backupConfig.mailList != gEmptyStr:
        print("Send backup archive via email...")
        ret, hostname = commands.getstatusoutput("hostname")
        if ret != 0:
            hostname = "unknown host"
        mailSubject = "host backup on %s from %s" % (plainTime, hostname)
        mailContent = mailSubject
        if gBackupErrorMsg:
            mailContent += ("\n\nError messages:\n" + gBackupErrorMsg)
        muttCmd = "echo '%s' | mutt -a '%s' -s '%s' -- %s" % (mailContent, backupArchive, mailSubject, backupConfig.mailList.replace(":", " "))
        os.system(muttCmd)

def check_cmds():
    cmdList = [
            "git --help",
            "mutt --help",
            ]

    for cmd in cmdList:
        ret = commands.getstatusoutput(cmd)[0]
        if ret != 0:
            print("Command %s not found. Please install it first." % cmd)
            return False

    return True

# check and extract backup archive
def restore(backupArchive):
    global gTmpDir

    if not os.path.exists(backupArchive):
        print("archive file %s not exists, program exits." % backupArchive)
    else:
        print("Extract host backup file...")
        os.system("tar -C %s -xpf %s" % (gTmpDir, backupArchive))

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
    if removeExistFirst and removeExistFirst != gEmptyStr:
        os.system("rm -Rf %s" % (" ".join(fileList)))
    os.system("tar -C / -xpf host-files-backup-*.tar.bz2")
    # change owner of files if set
    for fln in fileListNames:
        currListStr = configParser.get(FileListSection, fln)
        if configParser.has_option(OwnerListSection, fln):
            os.system("chown -R %s %s" % (configParser.get(OwnerListSection, fln), currListStr.replace(sepChar, " ")))

if __name__ == "__main__":
    if not check_cmds():
        print("Error checking commands")
        sys.exit(1)

    options, args = parse_cmd_options()

    # archive name of backup files
    currTime = time.strftime(gDateFormat, time.localtime())
    plainTime = time.strftime(gDefaultDateFormat, time.localtime())
    allBackupArchive = "host-backup-%s.tar" % (currTime)
    filesBackupArchive = "%s/host-files-backup-%s.tar.bz2" % (gTmpDir, currTime)
    dbBackupArchive = "%s/host-db-backup-%s.tar.bz2" % (gTmpDir, currTime)
    repoBackupArchive = "%s/host-repo-backup-%s.tar.bz2" % (gTmpDir, currTime)
    configFile = os.path.basename(options.config)
    configFileAbs = os.path.abspath(configFile)

    # parse config file
    bkConfig = BackupConfig(options.config)
    if not bkConfig.parse():
        print("Error parsing config file")
        sys.exit(1)

    if options.backup:
        backup_db(bkConfig, dbBackupArchive)
        backup_files(bkConfig, filesBackupArchive)
        if bkConfig.repoRoot != gEmptyStr and os.path.exists(bkConfig.repoRoot):
            backup_repos(bkConfig, repoBackupArchive)

    # archive all backup files including the config file
    allBackupFiles = ""
    if os.path.exists(dbBackupArchive):
        allBackupFiles += (" " + os.path.basename(dbBackupArchive))
    if os.path.exists(filesBackupArchive):
        allBackupFiles += (" " + os.path.basename(filesBackupArchive))
    if os.path.exists(repoBackupArchive):
        allBackupFiles += (" " + os.path.basename(repoBackupArchive))

    print("Archive all backup files to %s..." % (allBackupArchive))
    gBackupErrorMsg += run_cmd("tar -C %s -cf %s %s" % (gTmpDir, allBackupArchive, allBackupFiles))[1]

    if gBackupErrorMsg:
        print(gBackupErrorMsg)

    # send backup file via email
    if bkConfig.backupWithEmail != gEmptyStr and bkConfig.mailList != gEmptyStr:
        send_via_email(bkConfig, allBackupArchive)

    # upload to dropbox
    if bkConfig.backupWithDropbox != gEmptyStr and bkConfig.backupWithDropbox:
        upload_to_dropbox(bkConfig, allBackupArchive)

    # remove backup file
    if options.backup and bkConfig.removeAfterBackup and bkConfig.removeAfterBackup != gEmptyStr:
        os.system("rm -f %s" % (allBackupArchive))

    # remove tmp files
    print("Remove temp files...")
    os.system("rm -Rf %s" % gTmpDir)

    # update config file
    with open(options.config, "w") as f:
        bkConfig.configParser.write(f)
    print("Task finished")

