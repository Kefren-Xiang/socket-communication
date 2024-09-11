#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <sstream>
#include <ctime>
#include <algorithm>
#include <chrono>
#include <thread>
#include <atomic>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <mutex>  // 添加这个头文件
#include <vector> // 添加这个头文件
#pragma comment(lib, "ws2_32.lib")

// 验证用户的函数
bool authenticate(const std::string& username, const std::string& password) {
    return (username == "KefrenXiang" && password == "XZH242608xzh") ||
        (username == "EffieHe" && password == "HYF082506hyf");
}

// 记录日志的函数
void logInfo(const std::string& message) {
    std::time_t now = std::time(nullptr);
    std::tm localTime;
    localtime_s(&localTime, &now);

    char timeBuffer[100];
    strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", &localTime);

    std::cout << "[" << timeBuffer << "] " << message << std::endl;
}

// Base64编码函数
std::string base64Encode(unsigned char const* bytes_to_encode, unsigned int in_len) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, bytes_to_encode, in_len);
    BIO_flush(bio);
    BUF_MEM* bufferPtr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded_data(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return encoded_data;
}

// 处理WebSocket握手
bool handleWebSocketHandshake(SOCKET clientSocket) {
    char buffer[1024];
    int valread = recv(clientSocket, buffer, 1024, 0);
    if (valread <= 0) {
        return false;
    }

    std::string request(buffer, valread);
    std::string key;

    // 查找"Sec-WebSocket-Key"头部
    size_t keyPos = request.find("Sec-WebSocket-Key:");
    if (keyPos != std::string::npos) {
        keyPos += 19;
        size_t end = request.find("\r\n", keyPos);
        key = request.substr(keyPos, end - keyPos);
    }
    else {
        return false;
    }

    // 生成WebSocket Accept Key
    std::string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string combined = key + guid;

    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(combined.c_str()), combined.size(), hash);

    std::string acceptKey = base64Encode(hash, SHA_DIGEST_LENGTH);

    // 构建HTTP响应头
    std::ostringstream response;
    response << "HTTP/1.1 101 Switching Protocols\r\n";
    response << "Upgrade: websocket\r\n";
    response << "Connection: Upgrade\r\n";
    response << "Sec-WebSocket-Accept: " << acceptKey << "\r\n\r\n";

    // 发送响应
    send(clientSocket, response.str().c_str(), response.str().size(), 0);
    return true;
}

// 解析并解码 WebSocket 数据帧
std::string decodeWebSocketFrame(const char* buffer, int length) {
    if (length < 2) {
        return "";
    }

    unsigned char secondByte = buffer[1];
    unsigned long long payloadLength = secondByte & 0x7F;

    int maskIndex = 2;
    if (payloadLength == 126) {
        maskIndex = 4;
    }
    else if (payloadLength == 127) {
        maskIndex = 10;
    }

    unsigned char masks[4];
    std::copy(buffer + maskIndex, buffer + maskIndex + 4, masks);

    int dataIndex = maskIndex + 4;
    std::string decodedMessage;
    for (size_t i = dataIndex; i < length; ++i) {
        decodedMessage += buffer[i] ^ masks[(i - dataIndex) % 4];
    }

    return decodedMessage;
}

// 编码 WebSocket 数据帧
std::string encodeWebSocketFrame(const std::string& message) {
    std::string frame;
    size_t messageLength = message.size();

    frame += 0x81; // FIN bit set and text frame opcode

    if (messageLength <= 125) {
        frame += static_cast<char>(messageLength);
    }
    else if (messageLength <= 65535) {
        frame += 126;
        frame += static_cast<char>((messageLength >> 8) & 0xFF);
        frame += static_cast<char>(messageLength & 0xFF);
    }
    else {
        frame += 127;
        for (int i = 7; i >= 0; i--) {
            frame += static_cast<char>((messageLength >> (i * 8)) & 0xFF);
        }
    }

    frame += message;
    return frame;
}

// 修剪字符串的函数，移除首尾的空格和其他非可见字符
std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

// 获取当前时间的字符串表示
std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    char buffer[100];
    ctime_s(buffer, sizeof(buffer), &now_time);
    buffer[strlen(buffer) - 1] = '\0'; // 去掉换行符
    return std::string(buffer);
}

std::atomic<int> activeClients(0); // 跟踪活跃客户端数
std::atomic<bool> serverRunning(true); // 控制服务器是否继续运行
std::mutex clientsMutex;  // 保护客户端列表的互斥锁
std::vector<SOCKET> clients;  // 存储所有已连接的客户端

// 发送消息给所有已连接的客户端
void broadcastMessage(const std::string& message, SOCKET senderSocket, const std::string& senderInfo) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    std::string fullMessage = senderInfo + " says: " + message; // 将发送者信息附加到消息中
    for (SOCKET client : clients) {
        if (client != senderSocket) {  // 不发送给发送者自己
            std::string encodedMessage = encodeWebSocketFrame(fullMessage);
            send(client, encodedMessage.c_str(), encodedMessage.size(), 0);
        }
    }
}

void handleClient(SOCKET clientSocket) {
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.push_back(clientSocket);  // 将客户端加入列表
    }

    activeClients++;
    logInfo("Active clients: " + std::to_string(activeClients));

    // 获取客户端的IP地址和端口号
    sockaddr_in client_addr;
    int addr_len = sizeof(client_addr);
    getpeername(clientSocket, (sockaddr*)&client_addr, &addr_len);

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    std::string clientInfo = "Client " + std::string(client_ip) + ":" + std::to_string(client_port);
    logInfo(clientInfo + " connected.");

    // 处理WebSocket握手
    if (!handleWebSocketHandshake(clientSocket)) {
        logInfo("WebSocket handshake failed.");
        closesocket(clientSocket);
        activeClients--;
        return;
    }
    logInfo("WebSocket handshake successful!");

    char buffer[1024] = { 0 };
    bool authenticated = false;
    std::string username;  // 存储用户名

    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int valread = recv(clientSocket, buffer, 1024, 0);
        if (valread <= 0) {
            logInfo("Client disconnected.");
            break;
        }

        std::string decodedMessage = decodeWebSocketFrame(buffer, valread);
        if (decodedMessage.empty()) {
            continue;
        }

        decodedMessage = trim(decodedMessage);
        logInfo("[" + getCurrentTime() + "] Received: " + decodedMessage);

        // 处理认证逻辑
        if (decodedMessage.find("auth") != std::string::npos && !authenticated) {
            size_t userPos = decodedMessage.find("\"username\":\"");
            size_t passPos = decodedMessage.find("\"password\":\"");
            if (userPos != std::string::npos && passPos != std::string::npos) {
                username = decodedMessage.substr(userPos + 12, decodedMessage.find("\"", userPos + 12) - (userPos + 12));
                std::string password = decodedMessage.substr(passPos + 12, decodedMessage.find("\"", passPos + 12) - (passPos + 12));

                if (authenticate(username, password)) {
                    authenticated = true;
                    std::string authSuccess = "{\"type\":\"auth\",\"success\":true}";
                    std::string encodedMessage = encodeWebSocketFrame(authSuccess);
                    send(clientSocket, encodedMessage.c_str(), encodedMessage.size(), 0);
                    logInfo("Authentication successful for user: " + username);
                }
                else {
                    std::string authFail = "{\"type\":\"auth\",\"success\":false}";
                    std::string encodedMessage = encodeWebSocketFrame(authFail);
                    send(clientSocket, encodedMessage.c_str(), encodedMessage.size(), 0);
                    logInfo("Authentication failed for user: " + username);
                    closesocket(clientSocket);
                    activeClients--;
                    return;
                }
            }
        }
        else if (authenticated) {
            if (decodedMessage == "exit") {
                logInfo("[" + getCurrentTime() + "] Exiting the server...");
                break;
            }

            // 广播消息给其他客户端，并附加发送者的用户名或IP地址
            std::string senderInfo = username.empty() ? clientInfo : "User " + username;
            broadcastMessage(decodedMessage, clientSocket, senderInfo);
            logInfo("[" + getCurrentTime() + "] Message broadcasted by " + senderInfo);

            std::string responseMessage = "Echo: " + decodedMessage;
            std::string encodedMessage = encodeWebSocketFrame(responseMessage);
            send(clientSocket, encodedMessage.c_str(), encodedMessage.size(), 0);
        }
    }

    closesocket(clientSocket);
    activeClients--;

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(std::remove(clients.begin(), clients.end(), clientSocket), clients.end());
    }

    logInfo("Active clients: " + std::to_string(activeClients));
    if (activeClients == 0) {
        serverRunning = false;
    }
}

int main() {
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed." << std::endl;
        return 1;
    }

    // 创建Socket
    SOCKET server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == INVALID_SOCKET) {
        std::cerr << "Socket creation failed!" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    if (bind(server_fd, (sockaddr*)&address, sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "Bind failed!" << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }

    if (listen(server_fd, 3) == SOCKET_ERROR) {
        std::cerr << "Listen failed!" << std::endl;
        closesocket(server_fd);
        WSACleanup();
        return 1;
    }
    logInfo("Server is listening on port 8080...");

    // 接受多个客户端连接
    while (serverRunning) {
        SOCKET new_socket = accept(server_fd, NULL, NULL);
        if (new_socket == INVALID_SOCKET) {
            std::cerr << "Accept failed!" << std::endl;
            continue;
        }
        logInfo("Connection accepted!");

        // 创建一个新线程来处理客户端连接
        std::thread clientThread(handleClient, new_socket);
        clientThread.detach(); // 分离线程，让它独立运行
    }

    // 清理资源并停止服务器
    closesocket(server_fd);
    WSACleanup();
    logInfo("Server stopped.");
    return 0;
}
