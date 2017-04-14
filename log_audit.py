#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 用于SONY代码审计：对如拷贝回来的AIX和Linux系统日志，直接解压后将此脚本放入日志所在的文件夹，双击运行即可
# 运行后会生成audit_result.log文件，撰写报告时可以参考
# Attention: Python environment is needed
# Version 1.1.1
# 2014/12/03 Update: 删除auth日志中非安全事件
# Update:
# 2014-12-17:更新了对.bash_history日志的处理，删掉了带有#的内容
# 2015-02-03:为方便审计，自动将evt格式日志转换为evtx格式
# 2015-03-30：解压和重命名windows安全日志
# 2015-07-31：更新删除apache文件名
# 2015-12-11: 添加了readme函数
# 2016-01-15: 解决了一个溢出问题

# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# 注意，此脚本有很多的系统依赖，运行的时候需要保证所有调用os.system()的系统命令都 #
# 存在。建议在windows系统上运行，需要安装cygwin和7zip。                       #
# 脚本放入日志文件夹的根目录即可，如G:\201507                                 #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #



import os
import sys
import linecache
import random
import time
import tarfile
import re

def readme():
    '''
    请确认已经做好了以下准备工作:
    ----------------------------------------------------------------------
    ----------------------------------------------------------------------
    1.  备份整个日志目录.有些目录下脚本会删除原始日志文件
    ----------------------------------------------------------------------
    2.  确保系统环境支持.需要安装7ip, tar, gzip程序,并且将路径加入系统环境变量
    ----------------------------------------------------------------------
    3.  sony, sonystyle等四个目录需要手工解压缩日志文件并放入相应的目录
    ----------------------------------------------------------------------
    4.  默认会审计前两个月份的日志,可以加参数审计其他月份日志,如:
        python log_audit.py 10 9 ----- 审计9,10月份的日志
    ----------------------------------------------------------------------

                   ,
                   |'.             ,
                   |  '-._        / )
                 .'  .._  ',     /_'-,
                '   /  _'.'_\   /._)')
               :   /  '_' '_'  /  _.'
               |E |   |Q| |Q| /   /
              .'  _\  '-' '-'    /
            .'--.(S     ,__` )  /
                  '-.     _.'  /
                __.--'----(   /
            _.-'     :   __\ /
           (      __.' :'  :Y
            '.   '._,  :   :|
              '.     ) :.__:|
                \    \______/
                 '._L/_H____]
                  /_        /
                 /  '-.__.-')
                :      /   /
                :     /   /
              ,/_____/----;
              '._____)----'
              /     /   /
             /     /   /
           .'     /_   \__
           (_______)______)
    _____________________________________________________________________
    _____________________________________________________________________


    '''


# 解压tar.gz格式的压缩文件,系统需要安装tar,gzip程序
def extract(file):
    if 'tar.gz' in file:
        tar = tarfile.open(file)
        tar.extractall()
        tar.close()


# 解压所有文件（第一次解压缩）,会调用extract函数,本地需要安装7zip, tar程序,并加入系统环境变量
def uncompress():
    for root, dirs, files in os.walk(os.getcwd()):
        for file in files:
            match = re.search("os|apache|oracle|weblogic", file)
            if not match:
                continue
            if 'chk' in file or 'CHK' in file:
                continue
            if 'tar.gz' in file:
                os.chdir(root)
                # Bypass uncompressed
                if os.path.isdir(file[:-6]):
                    continue
                print '\n\n++++Uncompress file ' + os.path.join(root, file) + '++++'
                extract(file)
                continue
            if 'tar.Z' in file:
                os.chdir(root)
                # Bypass uncompressed
                if os.path.isdir(file[:-5]):
                    continue
                print '\n\n++++Uncompress file ' + os.path.join(root, file) + '++++'
                command = '7z x ' + file + ' >nul'
                os.system(command)
                command = 'tar -xf ' + file[:-2]
                os.system(command)
                os.remove(file[0:-2])
                continue
    os.chdir(root_dir)


# 对操作系统日志做预处理,预处理的结果会写入日志目录的abnormal.log文件
def os_audit():
    result = file('audit_result.log', 'w')
    if os.path.isfile('sh_history.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " sh_history"
        print line
        result.write('------' + line[4:] + '-----\n\n')
        f = file('sh_history.log', 'r')
        lenth = len(os.popen('cat sh_history.log').readlines())
        if lenth > 22:
            randline = random.randint(1, lenth - 20)
            for n in range(0, 20):
                tmp = linecache.getline('sh_history.log', randline + n)
                line = ""
                for char in tmp:
                    if char == "#":
                        line = line + '\n'
                        break
                    line = line + char
                if len(line) < 3:
                    continue
                result.write(line)
        else:
            for line in f.readline():
                result.write(line)
        f.close()

    # For last.log
    if os.path.isfile('last.log') and os.path.isfile('sh_history.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " last.log"
        print line
        result.write('\n------' + line[4:] + '-----\n\n')
        last = file('last.log', 'r')
        tmp = file('tmp.log', 'w')
        while True:
            line = last.readline()
            # if line[46:49]==cur_month_str:
            #	continue
            if len(line) == 0:
                break
            elif line[46:49] == cur_month_str:
                tmp.write(line)
            else:
                continue
        tmp.close()

        tmp = file('tmp.log', 'r')
        lenth = len(os.popen('cat tmp.log').readlines())
        if lenth > 7:
            randline = random.randint(1, lenth - 5)
            for n in range(0, 5):
                line = linecache.getline('tmp.log', randline + n)
                result.write(line)
        else:
            for line in tmp:
                result.write(line)

        tmp.close()
        os.remove('tmp.log')

    # For who.log
    if os.path.isfile('who.log') and os.path.isfile('sh_history.log'):
        line = line = "    Audit " + os.getcwd().split('\\')[-1] + " who.log"
        print line
        result.write("\n\n-----" + line[4:] + "-----\n\n")
        tmp = os.popen('cat who.log').readlines()
        for line in tmp:
            result.write(line)

    # For failedlogin.log
    if os.path.isfile('failedlogin.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " failedlogin.log"
        print line
        result.write("\n-----" + line[4:] + "-----\n\n")
        tmp = os.popen('tac failedlogin.log').readlines()
        f = file('failedlogin', 'w')
        for line in tmp:
            if len(line) < 5:
                continue
            if nex_month_str in line:
                continue
            elif cur_month_str in line:
                f.write(line)
            else:
                break
        f.close()
        tmp = os.popen('tac failedlogin').readlines()
        if len(tmp) > 50:
            f = file('failedlogin_result.txt', 'w')
        for line in tmp:
            if len(tmp) > 50:
                f.write(line)
            result.write(line)
        if len(tmp) > 50:
            f.close()

        os.remove('failedlogin')

    # For sulog
    if os.path.isfile('sulog.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " sulog"
        print line
        result.write('\n-----' + line[4:] + '-----\n\n')
        tmp = os.popen('tac sulog.log').readlines()
        f = file('tmp_su.log', 'w')
        for line in tmp:
            if len(line) == 0:
                break
            if line[0:5] == "SU " + cur_month_dit:
                f.write(line)
        f.close()

        f = file('tmp_su.log', 'r')
        lenth = len(os.popen('cat tmp_su.log').readlines())
        if lenth > 7:
            randline = random.randint(1, lenth - 5)
            for n in range(0, 5):
                line = linecache.getline('tmp_su.log', randline + n)
                result.write(line)
        else:
            for line in f.readline():
                result.write(line)

        f.close()
        os.remove('tmp_su.log')

    # For cronlog
    if os.path.isfile('cron.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " cronlog"
        print line
        result.write('\n-----' + line[4:] + '-----\n\n')
        tmp = os.popen('tac cron.log').readlines()
        f = file('tmp_cron.log', 'w')
        for line in tmp:
            if line[0:4] == "Cron":
                continue
            elif " " + nex_month_str + " " in line:
                continue
            elif " " + cur_month_str + " " in line:
                f.write(line)
            elif " " + for_month_str + " " in line:
                break
        f.close()

        f = file('tmp_cron.log', 'r')
        lenth = len(os.popen('cat tmp_cron.log').readlines())
        if lenth > 7:
            randline = random.randint(1, lenth - 5)
            for n in range(0, 5):
                line = linecache.getline('tmp_cron.log', randline + n)
                result.write(line)
        else:
            for line in f.readline():
                result.write(line)
        f.close()
        os.remove('tmp_cron.log')

    if os.path.isfile('auth.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " authlog"
        print line
        result.write('\n-----' + line[4:] + '-----\n\n')
        tmp = os.popen('tac auth.log').readlines()
        f = file('tmp_au.log', 'w')
        for line in tmp:
            if len(line) < 5:
                continue
            if line[0:3] == nex_month_str:
                continue
            elif line[0:3] == cur_month_str:
                f.write(line)
            else:
                break
        f.close()

        tmp = os.popen('tail tmp_au.log').readlines()
        result.write('Some sample logs:\n\n')
        for line in tmp:
            result.write(line)

        result.write('\nAbnormal log:\n\n')
        tmp = os.popen(
            'tac tmp_au.log|grep -i -E "failed|non-root|bad su"|grep -v -i "chan_read_failed|Connection reset by peer"|sort').readlines()
        if len(tmp) > 30:
            f = file('tmp_auth_result.txt', 'w')
        for line in tmp:
            if len(tmp) > 30:
                f.write(line)

            else:
                result.write(line)
        if len(tmp) > 30:
            print "    Refer to tmp_auth_result.txt for detail!"
            result.write("Refer to tmp_auth_result.txt for detail!\n")
            f.close()

        os.remove('tmp_au.log')

    # For auth.log
    if os.path.isfile('authlog.tar.gz'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " authlog"
        print line
        os.system('tar -zxf authlog.tar.gz 2>nul')
        os.chdir('var' + os.path.sep + 'log')
        result.write('\n-----' + line[4:] + '-----\n\n')
        files = os.listdir('.')
        for auth_file in files:
            if "2013" not in time.ctime(os.path.getmtime(auth_file)):
                os.remove(auth_file)

        tmp = os.popen('cat authlog*').readlines()
        f = file('tmp_au.log', 'w')
        for line in tmp:
            if line[0:3] == cur_month_str:
                f.write(line)

        f.close()

        result.write("Some sample logs:\n\n")
        count = 0
        while count <= 5 or count >= len(tmp):
            result.write(line)
            count = count + 1
        result.write("\n")

        tmp = os.popen('cat tmp_au.log|grep -i -E "failed|bad su|non-root"|grep -v chan_read_failed|sort').readlines()
        if len(tmp) > 30:
            f = file('tmp_auth_result.txt', 'w')
        result.write("\nAbnormal logs:\n\n")
        for line in tmp:
            if len(tmp) > 30:
                f.write(line)
            else:
                result.write(line)
        if len(tmp) > 30:
            print "    Refer to tmp_result.txt for detail!"
            result.write("Refer to tmp_auth_result.txt for detail!\n")
            f.close()

        if os.path.isfile('tmp_auth_result.txt'):
            os.system('cat tmp_auth_result.txt>auth_result.txt')
            os.system('mv auth_result.txt ../../')
        os.remove('tmp_au.log')

    ############################################For Linux#########################################

    # For sh_history.log
    if os.path.isfile('bash_history.log'):
        line = "\n    Audit " + os.getcwd().split('\\')[-1] + " bash_history"
        print line
        result.write("-----" + line[4:] + "-----\n\n")
        # Update: 2014/12/17
        # tmp=os.popen('tail -n 20 bash_history.log').readlines()
        tmp = os.popen('grep -v "#" bash_history.log|tail -n 20').readlines()
        for line in tmp:
            result.write(line)

    # For last.log
    if os.path.isfile('last.log') and os.path.isfile('bash_history.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " last.log"
        print line
        result.write("\n-----" + line[4:] + "-----\n\n")
        last = file('last.log', 'r')
        f = file('tmp', 'w')
        while True:
            line = last.readline()
            if len(line) == 0:
                break
            if cur_month_str in line:
                f.write(line)
        f.close()

        f = file('tmp', 'r')
        lenth = len(os.popen('cat tmp').readlines())
        if lenth == 0:
            print "    There are no records"
            result.write("There are no records!")
            result.write('\nThe lasted logs:\n\n')
            last = os.popen('tail -n 20 last.log')
            for line in last.readline():
                result.write(line)
        elif lenth < 7:
            for line in f.readline():
                result.write(line)
        else:
            randline = random.randint(1, lenth - 5)
            for n in range(0, 5):
                line = linecache.getline('tmp', randline + n)
                result.write(line)
        f.close()
        os.system('rm -fr tmp')

    # For who.log
    if os.path.isfile('who.log') and os.path.isfile('bash_history.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " who.log"
        print line
        result.write("\n-----" + line[4:] + "-----\n\n")
        tmp = os.popen('cat who.log').readlines()
        for line in tmp:
            result.write(line)

    # For lastlog.log
    if os.path.isfile('lastlog.log'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " lastlog"
        print line
        result.write('\n-----' + line[4:] + '-----\n\n')
        tmp = os.popen('cat lastlog.log').readlines()
        for line in tmp:
            result.write(line)

    # For cronlog
    if os.path.isfile('cronlog.tar.gz'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " cronlog"
        print line
        result.write('\n-----' + line[4:] + '-----\n\n')
        extract('cronlog.tar.gz')
        os.chdir('var' + os.path.sep + 'log')
        tmp = os.popen('cat cron*').readlines()
        f = file('tmp_cron.log', 'w')
        for line in tmp:
            if line[0:3] == cur_month_str:
                f.write(line)
        f.close()

        f = file('tmp_cron.log', 'r')
        lenth = len(os.popen('cat tmp_cron.log').readlines())
        if lenth == 0:
            print "    There are no records!"
            result.write("There are no records!\n\n")
        elif lenth > 7:
            randline = random.randint(1, lenth - 5)
            for n in range(0, 5):
                line = linecache.getline('tmp_cron.log', randline + n)
                result.write(line)
        else:
            for line in f.readline():
                result.write(line)

        f.close()
        os.remove('tmp_cron.log')
        os.chdir('..')
        os.chdir('..')

    # For secure log
    if os.path.isfile('secure.tar.gz'):
        line = "    Audit " + os.getcwd().split('\\')[-1] + " secure log"
        print line
        result.write('\n------' + line[4:] + '-----\n')
        extract('secure.tar.gz')
        os.chdir('var' + os.path.sep + 'log')
        tmp = os.popen('cat secure*').readlines()
        f = file('tmp_sec.log', 'w')
        for line in tmp:
            if line[0:3] == cur_month_str:
                f.write(line)
        f.close()

        result.write('\nSome sample log:\n\n')
        tmp = os.popen('head tmp_sec.log').readlines()
        for line in tmp:
            result.write(line)

        tmp = os.popen('tac tmp_sec.log|grep -i -E "failed|bad|non-root"|grep -v chan_read_failed|sort').readlines()
        result.write('\n\nAbnormal log:\n\n')
        if len(tmp) > 30:
            f = file('tmp_sec_result.txt', 'w')
            print "    Refer to tmp_result.txt for detail!"
            result.write('Refer to sec_result.txt for detail!\n')
            for line in tmp:
                f.write(line)
            f.close()
        elif len(tmp) == 0:
            print "    There are no abnormal logs!"
            result.write('\nThere are no abnormal logs')
        else:
            for line in tmp:
                result.write(line)
        if os.path.isfile('tmp_sec_result.txt'):
            os.system('mv tmp_sec_result.txt ../../sec_result.txt ')
        # os.remove('tmp_sec.log')

    result.close()


# 解压缩WEB日志,并且会删除原始文件
def apache_format():
    for files in os.listdir(os.getcwd()):
        if '.tar.gz' in files:
            extract(files)
            os.remove(files)
            continue
        if '.gz' in files:
            extract(files)
            os.remove(files)
            continue
        if '.Z' in files:
            command = '7z x ' + files + ' >nul'
            # print 'Uncompress '+files+'...'
            os.system(command)
            os.remove(files)
            continue


# 格式化审计出来的Apache,iis日志: 清除文件名,无效的内容等
def apache_result_format():
    if os.path.isdir('report'):
        os.chdir('report')

    for files in os.listdir(os.getcwd()):
        if '.txt' not in files:
            continue
        if len(open(files).read()) == 0:
            os.remove(files)
            continue
        r = file(files, 'r')
        f = file('tmp', 'w')

        while True:
            line = r.readline()
            if len(line) == 0:
                break

            if for_month_str in line:
                continue

            if line[9] == ':':
                line = line[10:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[10] == ':':
                line = line[11:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[12] == ':':
                line = line[13:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[13] == ':':
                line = line[14:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[14] == ':':
                line = line[15:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[16] == ':':
                line = line[17:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[19] == ':':
                line = line[20:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[20] == ':':
                line = line[21:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[21] == ':':
                line = line[22:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[23] == ':':
                line = line[24:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[24] == ':':
                line = line[25:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

            if line[26] == ':':
                line = line[27:]
                if line[0] == '-':
                    line = line[2:]
                f.write(line)
                continue

        r.close()
        f.close()

        if len(open('tmp').read()) != 0:
            command = 'mv tmp ' + files
            os.system(command)
        else:
            os.remove('tmp')


# 审计WEB日志:Apache,IIS日志; 审计结果会写入日志目录的report文件夹
def apache_audit():
    apache_format()
    apache_format()

    os.mkdir('report')
    # Audit apache log
    print '    Step 1, 7 left, wait...'
    os.system('grep -E -i "and 1=1|or 1=1|select\+|select%20" *log*|grep -E -v -i "[a-z]select|select[a-z]" >./report/1.sql_injection_attacks.txt')
    # os.system('grep -E -i "and 1=1|or 1=1|select\+|select%20" *log*|grep -E -v -i "[a-z]select|select[a-z]|_select|select_|\?select|=select|/select|select " >./report/1.sql_injection_attacks.txt')
    print '    Step 2, 6 left, wait...'
    os.system('grep -E -i  "<script|onload|onmouseover" *log*|grep -E -i -v "onload.js|[a-z]onload">./report/2.cross_site.txt')
    print '    Step 3, 5 left, wait...'
    os.system('grep -E -i  "AAAAAAAAAAAAAAAAAAA" *log*>./report/3.overflow_attack.txt')
    print '    Step 4, 4 left, wait...'
    os.system('grep -E -i  "\/etc\/passwd|\/etc\/shadow" *log*>./report/4.sensitive_file_access.txt')
    print '    Step 5, 3 left, wait...'
    os.system('grep -E  " 401 "  *log*|grep -E -v " 200 401">./report/5.http_authentication.txt')
    print '    Step 6, 2 left, wait...'
    os.system('grep -E "\/admin\/" *log*|grep -E " 404 ">./report/6.file_and_directory_foce.txt')
    print '    Step 7, 1 left, wait...'
    os.system('grep -E -i  "\.\.\/\.\.\/" *log*>./report/7.exceed_auth.txt')
    print '    Step 8, 0 left, wait...'
    os.system(
        'grep -E  "OPTIONS|DELETE" *log*|grep -E  -v "OPTIONS \/ HTTP\/1.1| 200 ">./report/8.server_inf_detection.txt')

    print '    OK, finished! Then format result, wait...'
    apache_result_format()


# 审计日志的主函数,会调用系统日志和WEB日志审计的函数
def log_audit():
    for root, dirs, files in os.walk(root_dir):
        for dir in dirs:
            if '_os' in dir:
                print '\n\n++++Audit OS log ' + os.path.join(root, dir) + '++++'
                os.chdir(os.path.join(root, dir))
                # Bypass audited
                if os.path.isfile('audit_result.log'):
                    f = file('audit_result.log', 'r')
                    line = f.readline()
                    line = f.readline()
                    if len(line) == 1 and len(f.readline()) == 1:
                        f.close()
                        os.remove('audit_result.log')
                        os_audit()
                else:
                    os_audit()

            if '_apache' in dir or dir == 'IIS' or dir == 'iis' or dir == 'bizsony' or dir == 'bizsonystyle' or dir == 'servicesony' or dir == 'sony' or dir=='sonystyle':
                if 'chk' in dir or 'CHK' in dir:
                    continue
                print '\n\n++++Audit apache log ' + os.path.join(root, dir) + '++++'
                os.chdir(os.path.join(root, dir))
                if os.path.isdir('report'):
                    continue
                apache_audit()

            if dir == 'os' or dir == 'OS':
                os.chdir(os.path.join(root, dir))
                if os.path.isfile('sec.evt') or os.path.isfile('SEC.evt'):
                    if not os.path.isfile('sec.evtx'):
                        print '\n\n++++Format OS log ' + os.path.join(root, dir) + '++++'
                        if os.path.isfile('sec.evt'):
                            command = "wevtutil epl sec.evt sec.evtx /lf:true"
                        if os.path.isfile('SEC.evt'):
                            command = "wevtutil epl SEC.evt sec.evtx /lf:true"
                        os.system(command)
                else:
                    os.system('7z x *.zip >nul')
                    os.system('rm -fr *.zip')
                    # os.rename(os.listdir('.')[0], 'sec.'+os.listdir('.')[0].split('.')[-1])
                    for sec_log in os.listdir('.'):
                        if sec_log.split('.')[-1] != 'evtx':
                            command = "wevtutil epl " + sec_log + " " + sec_log.replace(sec_log.split('.')[-1],'evtx') + " /lf:true"
                            os.system(command)

#主函数
if __name__ == '__main__':
    print readme.__doc__

    choice = raw_input("确认无误后,请输入 [YES|yes|Y|y] 开始日志审计 -->>:")
    sure = ('YES', 'yes', 'Y', 'y')
    if not choice in sure:
        print "\n你还没有准备好,程序退出!\n"
        exit()

    global root_dir
    global cur_month_str, nex_month_str, for_month_str
    global cur_month_dit, nex_month_dit, for_month_dit
    root_dir = os.getcwd()

#确认审计日志的月份,会接受用户输入的月份;如果无输入默认审计前两个月的日志
    month_str = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')
    month_dit = ('1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12')
    if len(sys.argv) > 2 and sys.argv[1] in month_dit and sys.argv[2] in month_dit:
        print sys.argv[1]
        print sys.argv[2]
        if int(sys.argv[1]) > int(sys.argv[2]):
            cur_month_dit = sys.argv[1]
            for_month_dit = sys.argv[2]
        else:
            cur_month_dit = sys.argv[2]
            for_month_dit = sys.argv[1]
        nex_month_dit = str((int(cur_month_dit) + 1)%12)
    else:
        cur_month_dit = str(time.gmtime()[1] - 1)
        nex_month_dit = str(time.gmtime()[1])
        for_month_dit = str(time.gmtime()[1] - 2)


    if int(cur_month_dit) <= 0:
        cur_month_dit = str(int(cur_month_dit) + 12)
    if int(for_month_dit) <= 0:
        for_month_dit = str(int(for_month_dit) + 12)
    cur_month_str = month_str[int(cur_month_dit) - 1]
    nex_month_str = month_str[int(nex_month_dit) - 1]
    for_month_str = month_str[int(for_month_dit) - 1]

    if len(for_month_dit) < 2:
        for_month_dit = '0' + for_month_dit
    if len(cur_month_dit) < 2:
        cur_month_dit = '0' + cur_month_dit
    if len(nex_month_dit) < 2:
        nex_month_dit = '0' + nex_month_dit

    print for_month_str
    print cur_month_str
    print nex_month_str
    print for_month_dit
    print cur_month_dit
    print nex_month_dit


    # exit()

    uncompress()
    log_audit()
    print '\n\nOK! All finished!'
    time.sleep(3600)
