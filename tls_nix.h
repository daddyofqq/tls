// SPDX-License-Identifier: GPL-3.0-only
/*
 *  tls_nix.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 *
 * This file contains platform dependent wrapper
 * (to deal with socket transport, threading, syncrhonization, etc.)
 *
 * It is aimed for a Unix/Linux like system
 *
 * It is a good reference or start point if you want to port to other system
 * like embedded system
 *
 */

#ifndef TLS_NIX_H
#define TLS_NIX_H

#include "debug.h"
#include "tiny_tls.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <errno.h>
#include <mutex>
#include <netdb.h>
#include <random>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>

namespace tiny_tls_ns
{
class NixTlsEnv : public TlsEnv
{
public:
    // core interface used by TLS to generate key materials
    virtual void get_randoms(uint8_t* ptr, size_t size) const override
    {
        static std::random_device rd;
        static std::default_random_engine dre(rd());
        std::uniform_int_distribution<int> di(0, 255);
        while (size--) {
            *ptr++ = static_cast<uint8_t>(di(dre));
        }
    }

    // needed time interface in 'yyyymmddhhmmss' format
    // used by TLS to check certificate expiry
    virtual std::string get_time() const override
    {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        tm local_tm = *localtime(&t);
        int year = (local_tm.tm_year + 1900);
        int month = local_tm.tm_mon + 1;
        int day = local_tm.tm_mday;
        int hour = local_tm.tm_hour;
        int minute = local_tm.tm_min;
        int second = local_tm.tm_sec;

        char buf[32];
        sprintf(buf, "%4d%02d%02d%02d%02d%02d", year, month, day, hour, minute, second);
        return std::string(buf);
    }
};

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

class TlsTcpConnect : public TlsConnect
{
    int sockfd;
    std::mutex m;

public:
    TlsTcpConnect() : sockfd(-1) {}

    virtual void lock() override
    {
        m.lock();
    }

    virtual void unlock() override
    {
        m.unlock();
    }

    int get_sockfd()
    {
        return sockfd;
    }

    bool connect(std::string const& name, uint16_t port)
    {
        struct hostent* server;

        server = ::gethostbyname(name.c_str());
        if (server == NULL) {
            pr_error("ERROR, no such host: ", name, "\n");
            return false;
        }

        struct sockaddr_in serv_addr;
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            pr_error("Error : Could not create socket \n");
            return false;
        }

        memset(&serv_addr, '0', sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);
        bcopy((char*)server->h_addr, (char*)&serv_addr.sin_addr.s_addr, server->h_length);

        if (::connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            printf("Error! Connect Failed : %s\n", strerror(errno));
            return false;
        }

        return true;
    }

    void recv_loop()
    {
        while (!shouldStop()) {
            unsigned expected = find_expected_size();
            if (expected <= 0) {
                pr_debug("cannot conintue to read anymore\n");
                return;
            }
            std::vector<uint8_t> buf(expected);
            int total = 0;
            while (total != expected) {
                int num = ::read(sockfd, &buf[total], expected - total);
                if (num <= 0) {
                    close_read();
                    return;
                }
                total += num;
            }
            handle_incoming_data(buf.data(), buf.size());
        }
    }

    void close()
    {
        if (sockfd >= 0) {
            shutdown();
            ::close(sockfd);
            sockfd = -1;
        }
    }

    virtual ~TlsTcpConnect()
    {
        close();
    }

    virtual bool transmit(const uint8_t* ptr, size_t size) override
    {
        pr_verbose("transmit ", std::vector<uint8_t>(ptr, ptr + size), "\n");
        return ::write(sockfd, ptr, size) == size;
    }
};

class DefaultTlsClient : public TlsClientConnection<Aes128GcmSha256,
                                                    X25519Alg,
                                                    Ed25519Alg>
{
    static inline NixTlsEnv defaultEnv;

    struct saved_psk_ticket {
        saved_psk_ticket(psk_ticket psk, std::chrono::time_point<std::chrono::steady_clock> start) : psk(psk), start(start){};
        psk_ticket psk;
        std::chrono::time_point<std::chrono::steady_clock> start;
    };

    TlsTcpConnect tcp;
    std::thread receiver;
    std::mutex m;
    std::condition_variable cv;
    std::deque<uint8_t> rx_buf;
    std::atomic<bool> error_condition;
    std::atomic<bool> eod;
    std::atomic<bool> ready;
    const std::string server_name;
    const uint16_t server_port;
    std::unique_ptr<saved_psk_ticket> res_psk_status; // resumption psk
    std::unique_ptr<saved_psk_ticket> ext_psk_status; // external psk

    std::function<bool()> have_data = [&]() { return eod.load() || error_condition.load() || rx_buf.size() != 0; };
    std::function<bool()> is_ready = [&]() { return ready.load() || error_condition.load(); };

public:
    using base = TlsClientConnection<Aes128GcmSha256, X25519Alg, Ed25519Alg>;

    DefaultTlsClient(Certificate& ca, std::string server_name, uint16_t server_port) : base(DefaultTlsClient::defaultEnv, ca),
                                                                                       server_name(server_name),
                                                                                       server_port(server_port)
    {
    };

    DefaultTlsClient(Certificate& ca,
                     std::string server_name,
                     uint16_t server_port,
                     secure_vector psk_secret,
                     secure_vector label) : base(DefaultTlsClient::defaultEnv, ca),
                                            server_name(server_name),
                                            server_port(server_port)
    {

        psk_ticket psk;
        psk.lifetime = 0;
        psk.age_add = 0;
        psk.ticket = label;
        psk.secret = psk_secret;

        // NOTE:
        // for a external PSK, we should always set max_early_data_size to zero
        // this will prevent early data from being sent
        // This is due to the fact that 0-RTT data is (and has always been) subject to replay attack
        // considering external PSK do not have a expire date
        // It is difficult to implement a counter-measure from server side
        psk.max_early_data_size = 0;
        ext_psk_status = std::make_unique<saved_psk_ticket>(psk, std::chrono::steady_clock::now());
    };

    ~DefaultTlsClient()
    {
        close();
    }

    bool connect()
    {
        if (tcp.get_sockfd() >= 0) {
            pr_error("cannot bind when there is a valid connection\n");
            return false;
        }

        pr_debug("connecting to ", server_name, ":", server_port, "\n");
        if (tcp.connect(server_name, server_port)) {
            error_condition.store(false);
            eod.store(false);
            ready.store(false);
            psk_info info;

            // choose external PSK first, if available
            if (ext_psk_status) {
                info.ticket_age = 0;
                info.identity = ext_psk_status->psk.ticket;
                info.secret = ext_psk_status->psk.secret;
                info.max_early_data_size = ext_psk_status->psk.max_early_data_size;
            } else if (res_psk_status) {
                info.ticket_age = 0;
                info.identity = res_psk_status->psk.ticket;
                info.secret = res_psk_status->psk.secret;
                info.max_early_data_size = res_psk_status->psk.max_early_data_size;
                if (res_psk_status->psk.lifetime != 0) {
                    auto end = std::chrono::steady_clock::now();
                    auto d = std::chrono::duration_cast<std::chrono::milliseconds>(end - res_psk_status->start).count();
                    if (d < res_psk_status->psk.lifetime * 1000) {
                        info.ticket_age = static_cast<uint32_t>(d + res_psk_status->psk.age_add);
                    } else {
                        pr_debug("psk has expired. RESET\n");
                        res_psk_status.reset();
                    }
                }
            }

            if (res_psk_status || ext_psk_status) {
                pr_debug("start TLS by using PSK\n");
                this->bind(&tcp, info);
            } else {
                this->bind(&tcp);
            }
            receiver = std::thread([&]() { tcp.recv_loop(); });
            return true;
        }

        return false;
    }

    void close()
    {
        if (tcp.get_sockfd() >= 0) {
            tcp.close();
            rx_buf.resize(0);
            if (receiver.joinable())
                receiver.join();
        }
    }

    size_t write_tls(const uint8_t* ptr, size_t size)
    {
        while (true) {
            std::unique_lock<std::mutex> ul(m);
            cv.wait(ul, is_ready);

            if (error_condition.load()) {
                break;
            }

            if (ready.load()) {
                bool ret = tcp.write_tls(ptr, size);
                if (ret)
                    return size;
                break;
            }
        }

        return -1;
    }

    int read_tls(uint8_t* buf, size_t size, bool block = true)
    {
        while (true) {
            std::unique_lock<std::mutex> ul(m);
            if (rx_buf.size() == 0 && !block) {
                return 0;
            }
            cv.wait(ul, have_data);
            if (rx_buf.size() != 0) {
                int actual = 0;
                while (size && rx_buf.size() != 0) {
                    *buf++ = rx_buf.front();
                    rx_buf.pop_front();
                    actual++;
                }
                return actual;
            } else if (error_condition.load()) {
                return -1;
            } else if (eod.load()) {
                return 0;
            }
        }
    }

    virtual void onReceive(const uint8_t* ptr, size_t size) override
    {
        std::unique_lock<std::mutex> ul(m);
        while (size--) {
            rx_buf.push_back(*ptr++);
        }
        cv.notify_all();
    }

    virtual void onError(TlsError error) override
    {
        std::unique_lock<std::mutex> ul(m);
        pr_error("TLS error code : ", static_cast<int>(error), "\n");
        if (error != TlsError::close_notify) {
            pr_debug("setting error condition\n");
            error_condition.store(true);
        }
    }

    virtual void end_of_data() override
    {
        std::unique_lock<std::mutex> ul(m);
        eod.store(true);
        cv.notify_all();
    }

    virtual void onReady() override
    {
        std::unique_lock<std::mutex> ul(m);
        pr_debug("TLS ready\n");
        ready.store(true);
        cv.notify_all();
    }

    // override this function if need PSK resume function
    virtual void onSavePskTicket(psk_ticket psk) override
    {
        using namespace std::chrono;
        pr_debug("get session ticket, time ", psk.lifetime, " seconds\n");
        pr_debug("identity ", psk.ticket, "\n");
        res_psk_status = std::make_unique<saved_psk_ticket>(psk, steady_clock::now());
    }
};
}; // namespace tiny_tls_ns

#endif

