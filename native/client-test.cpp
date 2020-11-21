#include "Asn1Node.h"
#include "Certificate.h"
#include "alg.h"
#include "cipher_suites.h"
#include "debug.h"
#include "default_rng.h"
#include "ecc_key_share.h"
#include "test_vector.h"
#include "tls_nix.h"
#include "utility.h"
#include <iostream>

using namespace tiny_tls_ns;

void Logger::log(const std::string& msg)
{
    std::cout << msg;
};

void Logger::log(const char* str)
{
    std::cout << std::string(str);
};

Logger logger{};

#if 0
void test(Certificate& ca)
{
    NixTlsEnv env;
    MockConnect mock(env, ca);
    TlsMockTester tester(mock);
    tester.run();
    exit(0);
}
#endif

static void interact(DefaultTlsClient& client, bool early_data = false)
{
    if (client.connect()) {
        if (early_data) {
            std::string hello = "\n\n********************* HELLO WORLD! **********************\n\n";
            client.write_tls(reinterpret_cast<uint8_t*>(hello.data()), hello.size());
        }

        while (true) {
            std::vector<uint8_t> buf;
            buf.resize(1024);
            auto ret = client.read_tls(buf.data(), buf.size());
            if (ret > 0) {
                buf.resize(ret);
                std::string cmd;
                for (auto x : buf)
                    cmd.push_back(static_cast<char>(x));
                std::cout << std::string("receive : ") << cmd;
                client.write_tls(buf.data(), buf.size());
                if (cmd.size() >= 4 && std::string(cmd.begin(), cmd.begin() + 4) == std::string("exit")) {
                    break;
                }
            } else {
                break;
            }
        }
        client.close();
    }
}

int main(int argc, char* argv[])
{
    auto ca_cert = hex2vector("30820225308201D7A00302010202140C30255730C3CBFD040F59AD3899272A1C22FED8300506032B6570308187310B3009060355040613024E5A3111300F06035504080C084175636B6C616E643111300F06035504070C084175636B6C616E64310D300B060355040A0C04584D616E31153013060355040B0C0C4372617A79204861636B65723110300E06035504030C07786D616E2D6361311A301806092A864886F70D010901160B636140786D616E2E636F6D301E170D3230313031353036323531325A170D3330313031333036323531325A308187310B3009060355040613024E5A3111300F06035504080C084175636B6C616E643111300F06035504070C084175636B6C616E64310D300B060355040A0C04584D616E31153013060355040B0C0C4372617A79204861636B65723110300E06035504030C07786D616E2D6361311A301806092A864886F70D010901160B636140786D616E2E636F6D302A300506032B657003210063347E25136F4325CF35AA5C57F2224A0C600FBEFFC30EA9A48C2B603E0531FDA3533051301D0603551D0E0416041466CC28D62A8682624A371F2FD377450096B8C51E301F0603551D2304183016801466CC28D62A8682624A371F2FD377450096B8C51E300F0603551D130101FF040530030101FF300506032B65700341009D7566941292E4994690B46E81EE327C7B323AA8BA80B5BE60C4FA24F9A0A27B9AAC8A12899FFC20BEDDB173315BCC6D1BBD384C06ACB09ABEE7BF57944F890B");
    Certificate ca;
    ca.parse(ca_cert.data(), ca_cert.size());

    if (argc > 1 && std::string(argv[1]) == std::string("-ext")) {
        // external psk case
        auto ext_psk = hex2vector("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        std::string hello = std::string("hello");
        pr_debug("using external psk : ", hello, " ", ext_psk, "\n");
        secure_vector ext_identity;
        for (auto x : hello)
            ext_identity.push_back(static_cast<uint8_t>(x));

        DefaultTlsClient client2(ca, "localhost", 9999, ext_psk, ext_identity);

        pr_debug("Testing External PSK ...\n");
        interact(client2, true);

        pr_debug("Testing Resume PSK after EXT ...\n");
        interact(client2, true);
    } else {
        DefaultTlsClient client(ca, "localhost", 9999);

        // normal case
        std::cout << "Testing normal TLS ...\n";
        interact(client);

        // PSK resumption case
        std::cout << "Testing TLS resumption ...\n";
        interact(client, true);
    }

    return 0;
}
