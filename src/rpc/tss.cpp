#include <rpc/server.h>
#include <rpc/util.h>
#include <logging.h>
#include "../script/DistributedSigner.h"
#include <util/strencodings.h>
#include <univalue.h>
#include <rpc/tss.h>
using util::ToString;

static RPCHelpMan setsigninggroup()
{
    return RPCHelpMan{
        "setsigninggroup",
        "Set the list of participant ports for the current signing group.\n",
        {
                {"ports", RPCArg::Type::STR, RPCArg::Optional::NO, "Comma-separated list of port numbers, e.g., \"3001,3002,3003\""}
        },
        RPCResult{
            RPCResult::Type::STR, "", "Confirmation message"
        },
        RPCExamples{
            HelpExampleCli("setsigninggroup", "\"3001,3002,3003\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string ports_str = self.Arg<std::string>("ports");
            std::vector<int> ports;
            size_t start = 0;
            size_t end = ports_str.find(',');

            while (end != std::string::npos) {
                std::string token = ports_str.substr(start, end - start);
                ports.push_back(std::stoi(token));
                start = end + 1;
                end = ports_str.find(',', start);
            }
            // last value (or only value if no commas)
            ports.push_back(std::stoi(ports_str.substr(start)));

            LogPrintf("📌 setsigninggroup received ports: ");
            for (int port : ports) {
                LogPrintf("%d ", port);
            }
            LogPrintf("\n");

            DistributedSigner::setSigningGroup(ports);
            return "Signing group ports updated.";
        }
    };
}


static RPCHelpMan setthreshold()
{
    return RPCHelpMan{
        "setthreshold",
        "Set the threshold values for the distributed signing protocol (t-of-n).\n",
        {
                    {"t", RPCArg::Type::STR, RPCArg::Optional::NO, "Threshold (number of required participants)."},
                    {"n", RPCArg::Type::STR, RPCArg::Optional::NO, "Total number of participants."},
                },
                RPCResult{
                    RPCResult::Type::STR, "", "Confirmation message"
                },
                RPCExamples{
                    HelpExampleCli("setthreshold", "2 3")
                },
                [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
                {
                    std::string t_str = self.Arg<std::string>("t");
                    std::string n_str = self.Arg<std::string>("n");

                    int t = std::stoi(t_str);
                    int n = std::stoi(n_str);

                    if (t <= 0 || n <= 0 || t > n) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid threshold values: t > 0, n > 0, and t <= n.");
                    }

                    LogPrintf("📌 setthreshold received t=%d, n=%d\n", t, n);
                    DistributedSigner::setThreshold(t, n);
                    return "Threshold updated to t = " + ToString(t) + ", n = " + ToString(n);
                }
    };
}

static RPCHelpMan reconstructsecret()
{
    return RPCHelpMan{
        "reconstructsecret",
        "Reconstruct the distributed secret using public key and list of ports.\n",
        {
                {"publicKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Hex-encoded public key."},
                {"ports", RPCArg::Type::STR, RPCArg::Optional::NO, "Comma-separated list of port numbers, e.g., \"3001,3002,3003\""}
        },
        RPCResult{
            RPCResult::Type::STR, "", "Confirmation message"
        },
        RPCExamples{
            HelpExampleCli("reconstructsecret", "\"02abcdef...\" \"3001,3002,3003\"")
        },
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue
        {
            std::string publicKey = self.Arg<std::string>("publicKey");
            std::string ports_str = self.Arg<std::string>("ports");

            std::vector<int> ports;
            size_t start = 0;
            size_t end = ports_str.find(',');

            while (end != std::string::npos) {
                ports.push_back(std::stoi(ports_str.substr(start, end - start)));
                start = end + 1;
                end = ports_str.find(',', start);
            }
            ports.push_back(std::stoi(ports_str.substr(start)));

            LogPrintf("📌 reconstructsecret received publicKey: %s\n", publicKey);
            LogPrintf("📌 ports: ");
            for (int port : ports) {
                LogPrintf("%d ", port);
            }
            LogPrintf("\n");

            DistributedSigner::reconstructSecret(publicKey, ports);
            LogPrintf("Secret reconstruction initiated.");

            return "Secret reconstruction initiated.";
        }
    };
}


void RegisterThresholdRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{

        {"tss", &setthreshold},
        {"tss", &setsigninggroup},
        {"tss", &reconstructsecret},
    };
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
