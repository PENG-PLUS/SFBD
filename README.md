# SFBD
Backdoor  后渗透工具  
  
  
# 简介
实现了后门程序基本功能，如命令行/上传/下载，并支持通信加密（rc4和简单的rot），实现了一些后渗透的功能，并嵌入了一些命令脚本。

**独特的实现：**
* 监控剪贴板，备份出现过的文本/图像/文件
* 监控回收站伪文件夹，记录变化并备份新增文件
* 监控前台的窗口信息，打印出类似时间表的记录

**有趣的东西：**
* 调整主音量
* 禁用键鼠
* 设置显示器亮度
* 获取经纬度
* 篡改程序/快捷方式图标

# 反病毒扫描
[这是链接 - https://www.virustotal.com/gui/file/84ecedcdd1efee0b07d52419c9968c5614006b15f6f186a2c26b69877675a238/detection](https://www.virustotal.com/gui/file/84ecedcdd1efee0b07d52419c9968c5614006b15f6f186a2c26b69877675a238/detection)
![scan](https://github.com/PENG-PLUS/SFBD/blob/main/scan.jpg)

# 使用
usage: SFBD.exe [-h] [--server/--client] <--option>  


detail:  

        --server                开启服务端模式  
        --client                开启客户端模式
        --listen-port           修改服务端模式下的监听端口，默认为5180
        --max-conn              修改服务端模式下会话的最大连接数，默认为10
        --host                  指定服务端IP用于连接，默认127.0.0.1
        --conn-port             指定服务端的端口号用于连接，默认5180
        --enc-mode <rc4/rot>    指定通信加密模式，默认为rc4
        --passwd                指定通信加密时使用的密钥，默认为backdoor
        --bufsize               指定接受消息的缓冲区大小（字节），默认为51800
        --log                   开启命令日志并指定日志文件名
        
# 主要功能  

func作用域  

|指令|介绍|
|:----:|:-----|
|screenshot|捕获当前屏幕截图|
|screen|录制本地屏幕|
|camera|调用摄像头进行拍照|
|video|调用摄像头录制视频|
|record|调用麦克风进行录音|
|lb_record|录制本地音频|
|keylogger|详细的键盘记录器|
|windows|持续监控处于前台的窗口信息|
|drives|监控新增的磁盘，复制指定文件|
|recyclebin|监控回收站的变化并备份新增文件|
|clip|监控剪贴板，备份文本/图像/文件|
|prompt_auth|弹出凭据验证窗口尝试钓鱼捕获凭据|
|chrome|解密Chrome浏览器中保存的凭据/Cookie|
|host_scan|多线程Ping扫描/端口扫描|
|installed|列出电脑上已安装的程序清单|
|sendkeys|批量发送按键|
|change_ico|更改程序/快捷方式的图标|
|play_audio|播放wav格式音频文件|
|volume|获取音量、设置音量和静音|
|volume_joke|循环设置音量最大并取消静音|
|disable|禁用键盘鼠标|
|light|检查并设置显示器亮度|
|adduser|通过Win32API创建普通用户|
|addgroup|通过Win32API添加用户到用户组|
|deluser|通过Win32API删除用户|
|setuser|通过Win32API更改用户密码/用户名|
|localbrute|通过尝试修改密码来爆破本地用户弱密码|
|lockscreen|设置电脑锁屏|
|swap_mouse|反转鼠标左右键|
|sleep|设置电脑睡眠或休眠|
|shutdown|设置电脑注销或关机|
|messagebox|弹窗，自定义文字|
|background|修改电脑壁纸|  
  
# 次要功能，一些命令脚本
  
cmds作用域  
   
|指令|介绍|
|:----:|:-----|
|listkb|列出系统上已安装的补丁|
|download|certutil命令下载文件|
|dormancy|设置电脑休眠|
|lock_screen|锁定屏幕|
|zip|ZIP压缩|
|screenshot|屏幕截图|
|disable_firewall|关闭防火墙|
|enable_firewall|开启防火墙|
|disable_network|禁用默认网络适配器|
|enable_network|启用默认网络适配器|
|disable_uac|关闭UAC（将弹出通知），重启生效|
|enable_uac|开启UAC|
|enable_rdp|开启远程桌面|
|disable_rdp|关闭远程桌面|
|disable_fail_rec|禁用windows故障恢复（管理员权限）|
|enable_fail_rec|启用windows故障恢复（管理员权限）|
|disable_AMSI|禁用AMSI（使其初始化失败）|
|enable_AMSI|启用AMSI|
|disable_defender|废除Windows默认杀软（不禁用，但使其不会再定义病毒）|
|set_defender|设置Windows默认杀软的排除项|
|location|获取当前位置的经纬度|
|listav|列出电脑上已安装的反病毒程序|
|prompt_auth|无限弹出账户验证弹窗直到用户输入正确密码|
|wifi_password|获取计算机上保存的WiFi凭据|
|check_msi|.msi安装程序提权检查（HKCU/HKLM，0x1为启用）|
|check_reg_pri|检查不安全的注册表权限（获取可以修改的服务二进制文件）|
|check_dir_pri|检查不安全的文件夹权限|
|check_path_quotes|检查没带引号的服务可执行程序路径|
|check_file_password|检查一些程序是否在磁盘留下凭据|
|check_reg_password|检查一些程序是否在注册表留下凭据|
|copy_any_file|复制任意文件（管理员权限）|
|rdp_log|查询远程桌面连接日志|
|clear_rdp_log|清除远程桌面日志痕迹|
|disable_office_pro|禁用office安全功能（不显示任何警告）|
|enable_pth|允许所有管理员进行哈希传递|
|disable_pth|禁止RID500以外管理员进行哈希传递|
|windows|获取系统当前的活动窗口列表|
|get_clip|获取剪贴板内容|
|set_clip|设置剪贴板内容|
|process|列出正在运行的进程和服务|
|services|列出系统上的服务列表|
|installed|列出系统上已安装的程序（Program Files文件夹）|
|i30|磁盘损坏漏洞（版本>1803）|
|delete_bak|删除windows系统上的一些备份文件|
|iehistory|查询IE浏览记录|
|clear_log|遍历删除所有类别的日志|
|netlm|启用NetNTLM降级|
|enable_crash_dump|开启系统崩溃的完全内存转储|
|disable_crash_dump|禁用系统的崩溃内存转储|
|enable_wdigest|启用WDigest UseLogonCredential|
|disable_wdigest|禁用WDigest UseLogonCredential|
|IFEO|设置映像劫持（退出时触发）|
|hijack|劫持一些windows内置程序以维持权限|
|wmi|WMI事件-权限维持|
|delwmi|删除注册的WMI事件|
|com|COM劫持-权限维持|
|reccom|COM劫持恢复默认值|
|clr|CLR劫持-权限维持|
|hidden_services|通过SDDL隐藏服务|
|display_services|通过SDDL取消隐藏服务|
|crash|让系统蓝屏（管理员权限）|
|fork|让电脑卡死|
|fork2|让电脑卡死|
|popup|无限弹窗（cmd窗口）|
