#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <mutex>
#include <thread>
#include <iostream>
#include <algorithm>

#pragma comment(lib, "ws2_32.lib")
using json = nlohmann::json;

struct U { SOCKET s; std::string n, k; };
std::vector<U> ulist;
std::mutex mx;

void send_all(const std::string& d) {
    std::lock_guard<std::mutex> lk(mx);
    for (const auto& u : ulist) send(u.s, d.c_str(), (int)d.size(), 0);
}

void sync_users() {
    json j = { {"type", "user_list"}, {"users", json::array()} };
    {
        std::lock_guard<std::mutex> lk(mx);
        for (auto& u : ulist) j["users"].push_back({ {"name", u.n}, {"key", u.k} });
    }
    send_all(j.dump());
}

void relay(const json& msg, const std::string& to) {
    std::lock_guard<std::mutex> lk(mx);
    for (const auto& u : ulist)
        if (u.n == to) {
            send(u.s, msg.dump().c_str(), (int)msg.dump().size(), 0);
            break;
        }
}

void handle(SOCKET s) {
    char buf[8192]{};
    int len = recv(s, buf, sizeof(buf), 0);
    if (len <= 0) return;

    try {
        auto j = json::parse({ buf, buf + len });
        std::string name = j["name"], key = j["key"];

        {
            std::lock_guard<std::mutex> lk(mx);
            for (const auto& u : ulist)
                if (u.n == name) {
                    json err = { {"type", "error"}, {"reason", "name_taken"} };
                    send(s, err.dump().c_str(), (int)err.dump().size(), 0);
                    closesocket(s);
                    return;
                }
            ulist.push_back({ s, name, key });
        }

        std::cout << "[+] " << name << " joined.\n";
        sync_users();

        while (true) {
            memset(buf, 0, sizeof(buf));
            int r = recv(s, buf, sizeof(buf), 0);
            if (r <= 0) break;

            std::string data(buf, r);
            try {
                auto msg = json::parse(data);
                if (msg.contains("to")) relay(msg, msg["to"]);
            }
            catch (...) {
                std::lock_guard<std::mutex> lk(mx);
                for (const auto& u : ulist)
                    if (u.s != s) send(u.s, data.c_str(), (int)data.size(), 0);
            }
        }
    }
    catch (...) {
        std::cerr << "[!] Handshake failed.\n";
    }

    {
        std::lock_guard<std::mutex> lk(mx);
        ulist.erase(std::remove_if(ulist.begin(), ulist.end(), [&](const U& u) { return u.s == s; }), ulist.end());
    }
    closesocket(s);
    sync_users();
}

int main() {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(5555);
    bind(srv, (sockaddr*)&addr, sizeof(addr));
    listen(srv, SOMAXCONN);

    std::cout << "[*] Server running on port 5555...\n";
    while (true) {
        sockaddr_in caddr{};
        int sz = sizeof(caddr);
        SOCKET cs = accept(srv, (sockaddr*)&caddr, &sz);
        if (cs != INVALID_SOCKET) std::thread(handle, cs).detach();
    }

    closesocket(srv);
    WSACleanup();
}
