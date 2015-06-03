# Host Backup
host-backup是一个用于网站备份的简单脚本，它使用tar备份文件，使用mysqldump备份mysql数据库，mongodump备份mongodb。并支持使用email和dropbox发送备份数据。

host-backup基于Apache License, Version 2.0发布，依赖于以下软件: python 2.6/2.7, GNU tar, mutt, mysql, dropbox sdk(如果需要dropbox功能).

详细说明文档可参考[这里](http://blog.atime.me/code/host_backup.html)。

