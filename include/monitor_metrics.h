// Copyright (C) 2026 James Hickman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#pragma once

// Prometheus exposition for the Poco-based bridges.
//
// **This header is copied verbatim between the bridges**, the same way
// fileservice.proto is. Keep the copies identical; per-service metrics belong at
// the call site, not in here.
//
// The names match what the core and the Python services publish — one
// `fileengine_` namespace with a `service` label, base units, `_total` on
// counters, HELP/TYPE on every family — so one scrape config and one dashboard
// covers the whole platform rather than a per-service dialect.
//
// The `process_*` family is reproduced from /proc under its standard names,
// because dashboards and alerts for those already exist. Per-thread STATE is
// included deliberately: a bridge parks worker threads, so a large count is
// normal and only `uninterruptible` (blocked in the kernel, uncancellable) and a
// persistently high not-waiting count indicate trouble.

#include <cstdint>
#include <dirent.h>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

namespace fileengine_monitor {

struct ThreadStates {
    bool available = false;
    int total = 0, running = 0, sleeping = 0, uninterruptible = 0;
    int stopped = 0, zombie = 0, other = 0;
    int not_waiting() const { return total - sleeping; }
};

inline ThreadStates read_thread_states() {
    ThreadStates s;
    DIR* dir = opendir("/proc/self/task");
    if (!dir) return s;
    while (dirent* e = readdir(dir)) {
        if (e->d_name[0] == '.') continue;
        std::ifstream f(std::string("/proc/self/task/") + e->d_name + "/stat");
        if (!f) continue;  // a thread can exit between listing and opening
        std::string line;
        std::getline(f, line);
        // Field 3 is the state, but field 2 is the command name in parentheses
        // and may itself contain spaces and parentheses — scan from the LAST ')'.
        const auto close = line.rfind(')');
        if (close == std::string::npos) continue;
        auto i = close + 1;
        while (i < line.size() && line[i] == ' ') ++i;
        if (i >= line.size()) continue;
        ++s.total;
        switch (line[i]) {
            case 'R': ++s.running; break;
            case 'S': ++s.sleeping; break;
            case 'D': ++s.uninterruptible; break;
            case 'T': case 't': ++s.stopped; break;
            case 'Z': ++s.zombie; break;
            default:  ++s.other; break;
        }
    }
    closedir(dir);
    s.available = s.total > 0;
    return s;
}

inline long resident_bytes() {
    std::ifstream f("/proc/self/status");
    std::string key;
    while (f >> key) {
        if (key == "VmRSS:") {
            long kb = 0;
            f >> kb;
            return kb * 1024;
        }
        std::string rest;
        std::getline(f, rest);
    }
    return 0;
}

inline int open_fds() {
    int n = 0;
    DIR* dir = opendir("/proc/self/fd");
    if (!dir) return 0;
    while (dirent* e = readdir(dir)) {
        if (e->d_name[0] != '.') ++n;
    }
    closedir(dir);
    return n;
}

class Writer {
public:
    explicit Writer(std::string service) : service_(std::move(service)) {}

    void family(const std::string& name, const std::string& help, const std::string& type) {
        if (declared_.count(name)) return;
        declared_[name] = true;
        out_ << "# HELP " << name << " " << help << "\n"
             << "# TYPE " << name << " " << type << "\n";
    }

    void sample(const std::string& name, double value, const std::string& extra = "") {
        out_ << name << "{service=\"" << service_ << "\"";
        if (!extra.empty()) out_ << "," << extra;
        out_ << "} " << fmt(value) << "\n";
    }

    void gauge(const std::string& name, const std::string& help, double value,
               const std::string& extra = "") {
        family(name, help, "gauge");
        sample(name, value, extra);
    }

    void counter(const std::string& name, const std::string& help, double value,
                 const std::string& extra = "") {
        family(name, help, "counter");
        sample(name, value, extra);
    }

    std::string str() const { return out_.str(); }

private:
    static std::string fmt(double v) {
        std::ostringstream o;
        if (v == static_cast<long long>(v)) o << static_cast<long long>(v);
        else o << v;
        return o.str();
    }
    std::string service_;
    std::ostringstream out_;
    std::map<std::string, bool> declared_;
};

// The process/thread block every service publishes identically.
inline void process_metrics(Writer& w) {
    if (const long rss = resident_bytes()) {
        w.gauge("process_resident_memory_bytes", "Resident memory size in bytes",
                static_cast<double>(rss));
    }
    w.gauge("process_open_fds", "Open file descriptors", open_fds());

    const auto th = read_thread_states();
    if (!th.available) return;
    w.gauge("process_threads", "Threads in this process", th.total);
    w.family("fileengine_threads",
             "Threads by kernel state. `uninterruptible` is blocked in the kernel and cannot "
             "be cancelled; a healthy idle service holds everything in `sleeping`", "gauge");
    w.sample("fileengine_threads", th.running, "state=\"running\"");
    w.sample("fileengine_threads", th.sleeping, "state=\"sleeping\"");
    w.sample("fileengine_threads", th.uninterruptible, "state=\"uninterruptible\"");
    w.sample("fileengine_threads", th.stopped, "state=\"stopped\"");
    w.sample("fileengine_threads", th.zombie, "state=\"zombie\"");
    w.sample("fileengine_threads", th.other, "state=\"other\"");
    w.gauge("fileengine_threads_not_waiting",
            "Threads not in interruptible sleep. An idle service should hold this near zero",
            th.not_waiting());
}

inline const char* content_type() { return "text/plain; version=0.0.4; charset=utf-8"; }

} // namespace fileengine_monitor
