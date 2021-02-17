#  BurpSuite Data Collector

[Engish README](README-en.md)


## 简介

BurpSuite 数据收集插件，可以收集请求历史中的参数名、目录、路径、子域名和文件名。
将这些数据保存在 MySQL 数据库中。导出时按出现的次数进行排序，生成排序好的字典。
出现次数多的排在前面。

## 功能

- 每十分钟自动导出一次数据到数据库，支持手动导出。
- 一键导出数据库中的字典到txt文件、csv文件。txt文件用于字典，csv文件用于导入，可导入其它人的csv文件来丰富字典。

## 使用

![usage](images/usage.png)

设置好数据库主机地址、端口、账号和密码。点击 connection test 来测试是否可以连接成功。

export data to database 可以手动导出数据到数据库。通常不用点，因为每十分钟会自动导出一次数据。

点击 save config 可以手动保存数据库连接信息，通常不用点，因为关闭时会自动保存连接信息。

点击 export data to files 可以导出数据库中的数据到 txt 文件和 csv 文件，数据已经按照出现次数进行排序。txt文件用于目录或者参数 fuzz，csv 文件用于共享和备份数据。

可以设置导出字典的最小count值。

点击 import dict from files 可以选择之前导出的 csv 文件导入到数据库。

![usage](images/dir_import.png)

![usage](images/dir.png)

## 合并字典

在 dicts 目录上有一些导出的字典，如果想分享自己的字典，请先使用插件把csv文件导入到自己的数据库，然后再导出csv文件，插件会自动合并导入的字典和数据库中的字典，然后在 github 提交一个pull request 来更新字典。

![我的安全专家之路](images/我的安全专家之路.png)
[从头开发一个BurpSuite数据收集插件 csdn](https://blog.csdn.net/qq_28205153/article/details/113831967) 
[从头开发一个BurpSuite数据收集插件 公众号](https://mp.weixin.qq.com/s?__biz=MzI5MTA1ODk5NQ==&tempkey=MTEwMF9jOVF0cVJoYVNqc2xEWncwNEduaU5sMlNERV9FbW4tSlJnbWVSbkxITmhPOVVuRkFGWTRudzNvWXJvWGNCQlRfMzNuR0R2dExQWERGYng3LVdSai1jLUJDcjhybHFfM3hfZlVJazd6WHFKN3V3SmhERHM0cUVKWUwzb1FJUkE3TENxdEZSQmRPUjc1V3FRd1NEOENUanZ0R284bFhuUG9Ic2tLVHF3fn4%3D&chksm=6c17275e5b60ae48c2bfe7ef69f31e556479bd6021c3465dd83ab5753e5a9a44334e75e986cd#rd)  

