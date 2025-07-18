#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <windows.h>
#include <nlohmann/json.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include <thread>
#include <string>
#include <map>
#include <mutex>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

using json = nlohmann::json;

std::string me;
std::map<std::string, std::string> keys;
EVP_PKEY* rsa = nullptr;
std::mutex io;

std::string b64e(const std::string& in) {
    BIO* b = BIO_new(BIO_s_mem()), * f = BIO_new(BIO_f_base64());
    BIO_set_flags(f, BIO_FLAGS_BASE64_NO_NL);
    BIO_push(f, b); BIO_write(f, in.data(), (int)in.size()); BIO_flush(f);
    BUF_MEM* buf; BIO_get_mem_ptr(f, &buf);
    std::string out(buf->data, buf->length); BIO_free_all(f); return out;
}

std::string b64d(const std::string& in) {
    char* tmp = new char[in.size()];
    BIO* b = BIO_new_mem_buf(in.data(), (int)in.size());
    BIO* f = BIO_new(BIO_f_base64()); BIO_set_flags(f, BIO_FLAGS_BASE64_NO_NL);
    b = BIO_push(f, b);
    int r = BIO_read(b, tmp, (int)in.size());
    std::string out(tmp, r); delete[] tmp; BIO_free_all(b); return out;
}

std::string gen_rsa() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY_keygen_init(ctx); EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096);
    EVP_PKEY_keygen(ctx, &rsa); EVP_PKEY_CTX_free(ctx);
    BIO* b = BIO_new(BIO_s_mem()); PEM_write_bio_PUBKEY(b, rsa);
    char* d; long l = BIO_get_mem_data(b, &d);
    std::string out(d, l); BIO_free(b); return out;
}

std::string rsa_enc(const std::string& pt, const std::string& pub) {
    BIO* b = BIO_new_mem_buf(pub.data(), (int)pub.size());
    EVP_PKEY* p = PEM_read_bio_PUBKEY(b, nullptr, nullptr, nullptr);
    BIO_free(b);
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(p, nullptr);
    EVP_PKEY_encrypt_init(c); EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING);
    size_t l = 0; EVP_PKEY_encrypt(c, nullptr, &l, (const uint8_t*)pt.data(), pt.size());
    std::string out(l, 0);
    EVP_PKEY_encrypt(c, (uint8_t*)&out[0], &l, (const uint8_t*)pt.data(), pt.size());
    EVP_PKEY_CTX_free(c); EVP_PKEY_free(p); out.resize(l); return out;
}

std::string rsa_dec(const std::string& ct) {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new(rsa, nullptr);
    EVP_PKEY_decrypt_init(c); EVP_PKEY_CTX_set_rsa_padding(c, RSA_PKCS1_OAEP_PADDING);
    size_t l = 0; EVP_PKEY_decrypt(c, nullptr, &l, (const uint8_t*)ct.data(), ct.size());
    std::string out(l, 0);
    EVP_PKEY_decrypt(c, (uint8_t*)&out[0], &l, (const uint8_t*)ct.data(), ct.size());
    EVP_PKEY_CTX_free(c); out.resize(l); return out;
}

std::string aes_enc(const std::string& pt, const std::string& key, std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new(); uint8_t iv_raw[16];
    RAND_bytes(iv_raw, 16); iv.assign((char*)iv_raw, 16);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (uint8_t*)key.data(), iv_raw);
    std::string out(pt.size() + 16, '\0'); int l = 0, t = 0;
    EVP_EncryptUpdate(ctx, (uint8_t*)&out[0], &l, (uint8_t*)pt.data(), pt.size()); t = l;
    EVP_EncryptFinal_ex(ctx, (uint8_t*)&out[0] + l, &l); t += l;
    EVP_CIPHER_CTX_free(ctx); out.resize(t); return out;
}

std::string aes_dec(const std::string& ct, const std::string& key, const std::string& iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (uint8_t*)key.data(), (uint8_t*)iv.data());
    std::string out(ct.size(), '\0'); int l = 0, t = 0;
    EVP_DecryptUpdate(ctx, (uint8_t*)&out[0], &l, (uint8_t*)ct.data(), ct.size()); t = l;
    EVP_DecryptFinal_ex(ctx, (uint8_t*)&out[0] + l, &l); t += l;
    EVP_CIPHER_CTX_free(ctx); out.resize(t); return out;
}

void recv_loop(SOCKET s) {
    char b[8192];
    while (true) {
        memset(b, 0, sizeof(b));
        int r = recv(s, b, sizeof(b), 0);
        if (r <= 0) break;
        try {
            std::string d(b, r);
            if (d.empty() || d[0] != '{') {
                std::cout << "\nPublic: " << d << "\n> ";
                continue;
            }
            auto j = json::parse(d);
            if (j["type"] == "user_list") {
                keys.clear();
                for (auto& u : j["users"]) keys[u["name"]] = u["key"];
            }
            else if (j["type"] == "message") {
                auto k = rsa_dec(b64d(j["key"]));
                auto p = aes_dec(b64d(j["data"]), k, b64d(j["iv"]));
                std::cout << "\nPM " << j["from"] << ": " << p << "\n> ";
            }
            else if (j["type"] == "error" && j["reason"] == "name_taken") {
                std::cerr << "[!] Name taken. Restart.\n"; exit(1);
            }
        }
        catch (...) {}
    }
}

void send_pm(SOCKET s, const std::string& to, const std::string& msg) {
    if (!keys.count(to)) return;
    std::string k = "this_is_32_bytes_aes_key_123456", iv;
    std::string enc = aes_enc(msg, k, iv);
    std::string ek = rsa_enc(k, keys[to]);
    json j = { {"type", "message"}, {"from", me}, {"to", to},
               {"key", b64e(ek)}, {"iv", b64e(iv)}, {"data", b64e(enc)} };
    send(s, j.dump().c_str(), (int)j.dump().size(), 0);
}

int main() {
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET;
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    a.sin_port = htons(5555); connect(s, (sockaddr*)&a, sizeof(a));

    std::cout << "Name: "; std::getline(std::cin, me);
    std::string pk = gen_rsa();
    json hello = { {"name", me}, {"key", pk} };
    send(s, hello.dump().c_str(), (int)hello.dump().size(), 0);

    std::thread t(recv_loop, s);
    std::string mode, to, msg;

    std::cout << "\nMode (public/private): ";
    std::getline(std::cin, mode);
    if (mode == "private") {
        std::cout << "To: "; std::getline(std::cin, to);
    }

    while (true) {
        std::cout << "> ";
        std::getline(std::cin, msg);
        if (msg == "/mode") {
            std::cout << "Switch (public/private): ";
            std::getline(std::cin, mode);
            if (mode == "private") {
                std::cout << "To: "; std::getline(std::cin, to);
            }
            continue;
        }
        if (msg == "/users") {
            std::cout << "Online:\n";
            for (const auto& [n, _] : keys) std::cout << " - " << n << "\n";
            continue;
        }
        if (mode == "public") {
            std::string m = me + ": " + msg;
            send(s, m.c_str(), (int)m.size(), 0);
        }
        else if (mode == "private") {
            send_pm(s, to, msg);
        }
    }

    t.join(); closesocket(s); WSACleanup();
}
