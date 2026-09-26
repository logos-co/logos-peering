#pragma once

// A facade: the local stand-in for a module imported from another runtime.
// It serves the import's name here and forwards each call upstream over
// tls_tcp, on a session per local consumer whose route peering_module
// grants. logos_host_remote runs one per process.

#include <chrono>
#include <memory>
#include <string>

struct lp_provider;

namespace logos::peering {

struct FacadeOptions {
    std::string name;         // the import's local name
    std::string transportSet; // where local consumers reach it
    std::string credential;   // this host's credential, from the runtime
    unsigned maxCalls = 16;
    std::string peering = "peering_module";
    // Shorter than a consumer's own deadline, so it sees remote/timeout.
    std::chrono::milliseconds callTimeout{25000};
    std::chrono::milliseconds retry{5000};
};

class Facade {
public:
    explicit Facade(FacadeOptions options);
    ~Facade();
    Facade(const Facade&) = delete;
    Facade& operator=(const Facade&) = delete;

    // Publishes the handshake object; the import's interface is fetched and
    // published in the background, and its state reported to peering_module.
    bool start(std::string& error);
    void stop();

    lp_provider* provider() const;

    struct Impl;

private:
    std::shared_ptr<Impl> impl_;
};

} // namespace logos::peering
