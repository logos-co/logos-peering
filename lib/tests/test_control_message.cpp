#include "logos/peering/control_message.h"

#include <gtest/gtest.h>

using namespace logos::peering;

TEST(ControlMessage, FramesSurviveArbitrarySplits)
{
    const auto a = encodeControlFrame(controlRequest(1, "exports.list", {}));
    const auto b = encodeControlFrame(controlPush("route.revoked", {{"generation", 3}}));
    std::vector<std::uint8_t> stream(a);
    stream.insert(stream.end(), b.begin(), b.end());
    ControlFrameDecoder decoder;
    std::vector<nlohmann::json> out;
    for (const std::uint8_t byte : stream) {
        decoder.feed(&byte, 1);
        while (auto message = decoder.next()) out.push_back(*message);
    }
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out[0]["type"], "exports.list");
    EXPECT_EQ(out[1]["body"]["generation"], 3);
    EXPECT_FALSE(decoder.failed());
}

TEST(ControlMessage, OversizeFramesFailBeforeTheBodyArrives)
{
    ControlFrameDecoder decoder(kPreAuthFrameLimit);
    const std::uint8_t header[] = {0x00, 0x01, 0x00, 0x00}; // 64 KiB announced
    decoder.feed(header, sizeof header);
    EXPECT_FALSE(decoder.next().has_value());
    EXPECT_TRUE(decoder.failed());
}

TEST(ControlMessage, NonObjectsAndDuplicateKeysFail)
{
    for (const std::string text : {std::string("[1]"), std::string(R"({"id":1,"id":2})")}) {
        std::vector<std::uint8_t> frame = {0, 0, 0, static_cast<std::uint8_t>(text.size())};
        frame.insert(frame.end(), text.begin(), text.end());
        ControlFrameDecoder decoder;
        decoder.feed(frame.data(), frame.size());
        EXPECT_FALSE(decoder.next().has_value());
        EXPECT_TRUE(decoder.failed()) << text;
    }
}

TEST(ControlMessage, RepliesAndErrors)
{
    EXPECT_EQ(controlReply(7, {{"x", 1}})["ok"], true);
    EXPECT_EQ(controlError(7, "NOT_AUTHORISED")["error"], "NOT_AUTHORISED");
    EXPECT_FALSE(controlPush("t", {}).contains("id"));
}
