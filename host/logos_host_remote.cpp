// logos_host_remote: hosts one facade, the local stand-in for a module
// imported from another runtime. Started by the runtime for a peer-facade
// record like logos_host_plain for a native module, without --path.

#include "logos/peering/facade.h"

#include <crash_handler.h>
#include <host_process.h>
#include <token_source.h>
#include <transport_set_arg.h>

#include <logos_transport_config_json.h>

#include <cstdlib>
#include <string>

#ifndef _WIN32
#include <sys/resource.h>
#endif

namespace {

using logos::host_process::reportLoadStatus;

struct Args {
    std::string name;
    std::string transportSet;
    std::string tokenSource;
    std::string concurrency = "single";
    int maxWorkers = 0;
    bool valid = false;
};

Args parse(int argc, char** argv)
{
    Args args;
    for (int i = 1; i < argc; ++i) {
        const std::string key = argv[i];
        if (i + 1 >= argc) return args;
        const std::string value = argv[++i];
        if (key == "--name") args.name = value;
        else if (key == "--transport-set") args.transportSet = value;
        else if (key == "--token-source") args.tokenSource = value;
        else if (key == "--concurrency") args.concurrency = value;
        else if (key == "--max-workers") args.maxWorkers = std::atoi(value.c_str());
        else if (key == "--instance-persistence-path" || key == "--host-services") continue;
        else return args;
    }
    args.valid = !args.name.empty()
        && (args.concurrency == "single" || args.concurrency == "multi");
    return args;
}

} // namespace

int main(int argc, char** argv)
{
    logos::host_process::prepare();
#ifndef _WIN32
    // It holds a private key for its sessions.
    const rlimit noCore{0, 0};
    setrlimit(RLIMIT_CORE, &noCore);
#endif
    const Args args = parse(argc, argv);
    if (!args.valid) {
        reportLoadStatus(false, "usage: logos_host_remote --name <import> [--transport-set <set>] "
                                "[--token-source <source>] [--concurrency single|multi]");
        return 1;
    }
    installCrashHandler(args.name.c_str());

    const std::string token = HostTokenSource::read(args.tokenSource);
    if (token.empty()) {
        reportLoadStatus(false, "no auth token arrived on "
            + (args.tokenSource.empty() ? std::string("stdin") : args.tokenSource));
        return 1;
    }
    const std::string transportSet =
        args.transportSet.empty() ? std::string("[]") : decodeTransportSetArg(args.transportSet);
    if (std::string problem; !logos::parseTransportSet(transportSet, nullptr, &problem)) {
        reportLoadStatus(false, "unusable --transport-set: " + problem);
        return 1;
    }

    logos::peering::FacadeOptions options;
    options.name = args.name;
    options.transportSet = transportSet;
    options.credential = token;
    options.maxCalls = args.concurrency == "multi" ? (args.maxWorkers > 0 ? args.maxWorkers : 16) : 1;
    logos::peering::Facade facade(options);
    if (std::string error; !facade.start(error)) {
        reportLoadStatus(false, error);
        return 1;
    }

    logos::host_process::installStopHandlers();
    reportLoadStatus(true);
    logos::host_process::waitForStop();
    facade.stop();
    return 0;
}
