// Copyright (c) 2018 IIS (The Internet Foundation in Sweden)
// Written by Göran Andersson <initgoran@gmail.com>

#pragma once

#include "task.h"
#include "socketreceiver.h"
#include "workerprocess.h"

class LoadBalancer : public Task {
public:

    LoadBalancer(const TaskConfig &tc);

    ~LoadBalancer() override;

    SocketConnection *newClient(int fd, const char *, uint16_t,
                                ServerSocket *) override;

    double start() override;
#ifdef USE_GNUTLS
    bool tlsSetKey(ServerSocket *conn, const std::string &crt_path,
                   const std::string &key_path,
                   const std::string &password) override;
#endif

    void serverRemoved(ServerSocket *s) override;
    void processFinished(int pid, int wstatus) override;
protected:
    size_t nextWorker() const {
        return next_worker;
    }
    void rotateNextWorker() {
        if (++next_worker >= worker_proc.size())
            next_worker = 0;
    }

    void doPass(int fd, size_t wid, ServerSocket *srv);
    void new_worker(size_t i);
    void removeWorker(pid_t pid);
    std::string workerConfig(unsigned int i=0) const {
        return worker_config + "\nworker_number " + std::to_string(i);
    }
    void setMaxRetries(unsigned int n) {
        max_retries = n;
    }
private:
#ifdef USE_GNUTLS
    std::map<ServerSocket *, unsigned int> portMap;
#endif
    unsigned int max_retries = 100;
    unsigned int no_channels = 1;
    std::vector<WorkerProcess *> worker_proc;
    std::vector<TimePoint> worker_proc_health;
    size_t next_worker = 0;
    TaskConfig my_config;
    std::string worker_config;
    size_t tot_no_workers;
};
