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
        --log                   开启命令日志并指定日志文件名，默认为SFBD.log
        
# 主要功能  

func作用域  

|指令|介绍|
|:----:|:----:|
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
