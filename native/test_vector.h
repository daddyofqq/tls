#ifndef TEST_VECTOR_H
#define TEST_VECTOR_H

#include "Certificate.h"
#include "cipher_suites.h"
#include "ecc.h"
#include "mpi.h"
#include "tiny_tls.h"

#include <string>

namespace tiny_tls_ns
{

class MockConnect : public TlsConnect, public TlsClientConnection<Aes128GcmSha256, X25519Alg, Ed25519Alg>
{
public:
    using base = TlsClientConnection<Aes128GcmSha256, X25519Alg, Ed25519Alg>;
    psk_ticket res;

    MockConnect(TlsEnv& env, Certificate& ca) : base(env, ca) {}

    ~MockConnect()
    {
    }

    void feed(const uint8_t* ptr, size_t size)
    {
        while (size) {
            int expected = find_expected_size();
            if (expected <= size) {
                handle_incoming_data(ptr, expected);
            } else {
                pr_debug("do not know how to feed data\n");
                exit(0);
            }
            ptr += expected;
            size -= expected;
        }
    }

    virtual bool transmit(const uint8_t* ptr, size_t size) override
    {
        pr_debug("+++ Mock transmit ", std::vector<uint8_t>(ptr, ptr + size), "\n");
        return true;
    }

    virtual void onReceive(const uint8_t* ptr, size_t size) override
    {
        pr_debug("+++ Mock receive TLS data: ", secure_vector(ptr, ptr + size), "\n");
    }

    virtual void onError(TlsError error) override
    {
        pr_debug("+++ Mock receive TLS error code : ", static_cast<int>(error), "+++\n");
        if (error != TlsError::close_notify) {
            exit(0);
        }
    }

    virtual void end_of_data() override
    {
        pr_debug("+++ Mock receive End of Data +++\n");
    }

    virtual void onReady() override
    {
        pr_debug("+++ Mock receive TLS ready +++\n");
    }

    virtual void onSavePskTicket(psk_ticket res)
    {
        pr_debug("+++ Mock receive resumption state +++\n");
        this->res = res;
    }

    virtual void lock() override
    {
    }

    virtual void unlock() override
    {
    }
};

static inline uint8_t hex2nibble(char h)
{
    if (h >= '0' && h <= '9')
        return h - '0';

    if (h >= 'A' && h <= 'F')
        return h - 'A' + 10;

    return (h - 'a' + 10) & 0x0F;
};

static inline secure_vector hex2vector(const std::string& hex)
{
    secure_vector v(hex.size() / 2);
    for (unsigned i = 0; i != v.size(); i++) {
        uint8_t b = hex2nibble(hex[i << 1]);
        b = (b << 4) | hex2nibble(hex[(i << 1) + 1]);
        v[i] = b;
    };
    return v;
};

// test vector from https://tools.ietf.org/html/draft-ietf-tls-tls13-vectors-06

class TlsMockTester
{
    MockConnect& mock;

public:
    TlsMockTester(MockConnect& mock) : mock(mock){};
    void run()
    {
        case_1rtt();
        case_0rtt();
    }

    void case_1rtt()
    {
        auto clientPrv = hex2vector(std::string("0161d7bf4ba06c3568f10954f0f1ca087460549cdc7bfeb2776b4604d82faac2"));
        auto clientHello = hex2vector(std::string("010000c00303d4b9503c5e95c9eecc99ce6376ccad4dcc06d7c8f1fa44b0d95600e9a0586c67000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d0020b0f5019fb0f1e5376b8b1dfb905f1d915161bac37707dad8907bd71b9807b345002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001"));
        auto serverHello = hex2vector(std::string("020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304"));
        auto serverHelloRecord = hex2vector(std::string("160303005a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304"));
        auto ecdhe = hex2vector(std::string("8151d1464c1b55533623b9c2246a6a0e6e7e185063e14afdaff0b6e1c61a8642"));
        auto server_hs = hex2vector(std::string("080000240022000a00140012001d00170018001901000101010201030104001c00024001000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f00008408040080754040d0ddab8cf0e2da2bc4995b868ad745c8e1564e33cde17880a42392cc624aeef6b67bb3f0ae71d9d54a2309731d87dc59f642d733be2eb27484ad8a8c8eb3516a7ac57f2625e2b5c0888a8541f4e734f73d054761df1dd02f0e3e9a33cfa10b6e3eb4ebf7ac053b01fdabbddfc54133bcd24c8bbdceb223b2aa03452a2914000020ac86acbc9cd25a45b57ad5b64db15d4405cf8c80e314583ebf3283ef9a99310c"));
        auto server_hs_encrypted = hex2vector(std::string("17030302A2F10B26D8FCAF67B5B828F712122216A1CD14187465B77637CBCD78539128BB93246DCCA1AF56F1EAA271666077455BC54965D85F05F9BD36D6996171EB536AFF613EEDDC42BAD5A2D2227C4606F1215F980E7AFAF56BD3B85A51BE130003101A758D077B1C891D8E7A22947E5A229851FD42A9DD422608F868272ABF92B3D43FB46AC420259346067F66322FD708885680F4B4433C29116F2DFA529E09BBA53C7CD920121724809EADDCC84307EF46FC51A0B33D99D39DB337FCD761CE0F2B02DC73DEDB6FDDB77C4F8099BDE93D5BEE08BCF2131F29A2A37FF07949E8F8BCDD3E8310B8BF8B3444C85AAF0D2AEB2D4F36FD14D5CB51FCEBFF418B3827136AB9529E9A3D3F35E4C0AE749EA2DBC94982A1281D3E6DAAB719AA4460889321A008BF10FA06AC0C61CC122CC90D5E22C0030C986AE84A33A0C47DF174BCFBD50BF78FFDF24051AB423DB63D5815DB2F830040F30521131C98C66F16C362ADDCE2FBA0602CF0A7DDDF22E8DEF7516CDFEE95B4056CC9AD38C95352335421B5B1FFBADF75E5212FDAD7A75F52A2801486A1EEC3539580BEE0E4B337CDA6085AC9ECCD1A0F1A46CEBFBB5CDFA3251AC28C3BC826148C6D8C1EB6A06F77F6FF632C6A83E283E8F9DF7C6DBABF1C6EA40629A85B43AB0C73D34F9D5072832A104EDA3F75F5D83DA6E14822A18E14099D749EAFD823CA2AC7542086501ECA206CE7887920008573757CE2F230A890782B99CC682377BEEE812756D04F9025135FB599D746FEFE7316C922AC265CA0D29021375ADB63C1509C3E242DFB92B8DEE891F7368C4058399B8DB9075F2DCC8216194E503B6652D87D2CB41F99ADFDCC5BE5EC7E1E6326AC22D70BD3BA652827532D669AFF005173597F8039C3EA4922D3EC757670222F6AC29B93E90D7AD3F6DD96328E429CFCFD5CCA22707FE2D86AD1DCB0BE756E8E"));
        auto new_session_ticket_encrypted = hex2vector(std::string("17030300de3680c2b2109d25caa26c3b06eea9fdc5cb31613ba702176596da2e886bf6af93507bd68161ad9cb4780653842e1041ecbf0088a65ac4ef438419dd1d95ddd9bd2ad4484e7e167d0e6c008448ae58a0418713b6fc6c51e4bb23a537fb75a74f73de31fe6aa0bc522515f8b25f8955428b5de5ac06762cec22b0aa78c94385ef8e70fa24945b7c1f268510871689bbbbfaf2e7f4a19277024f95f1143ab12a31ec63adb128cb390711fd6d06a498df3e98615d8eb102e23353b480efcca5e8e0267a6d0fe2441f14c8c9664aefb2cfff6ae9e0442728b6a0940c1e824fda06"));
        auto server_app_data1 = hex2vector(std::string("1703030043f65f49fd2df6cd2347c3d30166e3cfddb6308a5906c076112c6a37ff1dbd406b5813c0abd734883017a6b2833186b13c14da5d75f33d8760789994e27d82043ab88d65"));
        auto client_app_data1 = hex2vector(std::string("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031"));
        auto server_alert = hex2vector(std::string("1703030013f8141ebdb5eda511e0bce639a56ff9ea825a21"));

        mock.bind(&mock, secure_vector(clientPrv.begin(), clientPrv.end()),
                  secure_vector(clientHello.begin(), clientHello.end()));

        mock.feed(serverHelloRecord.data(), serverHelloRecord.size());

        mock.feed(server_hs_encrypted.data(), server_hs_encrypted.size());
        mock.feed(new_session_ticket_encrypted.data(), new_session_ticket_encrypted.size());
        mock.feed(server_app_data1.data(), server_app_data1.size());
        mock.write_tls(client_app_data1.data(), client_app_data1.size());

        mock.close_write();
        mock.feed(server_alert.data(), server_alert.size());
        mock.shutdown();
    }

    void case_0rtt()
    {
        auto clientPrv = hex2vector("539d7ebfa96c5ceb7d86f0b9682a1dd7b7b60d81c273507435cdd1b7aa80051f");
        auto clientHello = hex2vector("010001fc03038809d2a39bf9aeb3831d2b32e4fff93215e4fc4f25717971bd79e81941e3dd9b000006130113031302010001cd0000000b0009000006736572766572ff01000100000a00140012001d00170018001901000101010201030104003300260024001d0020b03199c34d682d91db5f589610f6c09bece99c23c77cc60d1edd0d25ed5dbe70002a0000002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c0002400100150057000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002900dd00b800b2ff099f9676cdff8b0bf8825d000000007905a9d28efeef4a47c6f9b06a0cecdb0070d920b898997c75b79636943ed42046a96142bd084a04acfa0c490f452d756dea02c0f927259f1f3231ac0d541a769129b740ce38090842b828c27fd729f59737ba98aa7b42e043c5da28f8dca8590b2df410d5134fd6c4cacad8b30370602afa35d265bf4d127976bb36dbda6a626f0270e20eebc73d6fcae2b1a0da122ee9042f76be56ebf41aa469c3d2c9da9197d82fd399320021203ce669dedec44e5e75538fccab3db045fb5d21011999e14512ee3ab35f2af4e9");

        // set age to a proper elapsed value in milliseconds
        psk_info info;
        info.ticket_age = 100 + mock.res.age_add; // adjust the age as you wish
        info.identity = mock.res.ticket;
        info.max_early_data_size = 4096;

        mock.bind(&mock, info,
                  secure_vector(clientPrv.begin(), clientPrv.end()),
                  secure_vector(clientHello.begin(), clientHello.end()));

        auto early_data = hex2vector("414243444546");
        mock.write_tls(early_data.data(), early_data.size());

        auto serverHello = hex2vector("16030300600200005c030322ac26b026b9d571702dad447e2d5a54d15ae1e06faf78358a3e177be83ace9400130100003400290002000000330024001d002027e0068f6efd825408eb88c74ee88dba83e351ed5a3749ae94505cfbd4e78928002b00020304");
        mock.feed(serverHello.data(), serverHello.size());

        auto serverFinished = hex2vector("170303006144c1e3836ba6a7ba0ded9d4cf817f32979d85c8b41da53b20955803d9ea2e342ef1affd66a028785e2196ad6a0dbdd27443d36872653c1968b0f9c01bdcfde83cfc1b843b78190abad0dc3ea30d1be40e3cec8961988cef4958fd16b7f1f9e4741");
        mock.feed(serverFinished.data(), serverFinished.size());
        auto clientData = hex2vector("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031");
        mock.write_tls(clientData.data(), clientData.size());
        auto serverData = hex2vector("170303004335da03f1bd93ac0982d88e1a9f6e0e8681c1a34c6e95eecfba1054c5a21100e87f2b78ab1fe5a43f39a58ee840bf97f5c91f973ace78eb92f827912f42316da17b22b9");
        mock.feed(serverData.data(), serverData.size());
    }
};

}; // namespace tiny_tls_ns

#endif
