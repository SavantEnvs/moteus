// Fuzz the BiSS-C absolute-encoder frame decoder (fw/bissc_extract.h, ExtractBisscFrame): the
// firmware samples the encoder's data line into a byte buffer via DMA and decodes START bit,
// data bits, status bits and CRC-6 from it. The sample buffer is device-controlled.
//
// Input: byte 0 -> pin_bit_pos (0-7), byte 1 -> data_bits (1..kMaxDataBits=58, the range
// fw/bissc.h accepts), byte 2 -> store_debug; the rest is the raw sample buffer.
// crc_bits is 6, the only value fw/bissc.h accepts.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "fw/bissc_extract.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 3) { return -1; }
  moteus::BisscExtractConfig config;
  config.pin_bit_pos = data[0] & 7;
  config.data_bits = 1 + (data[1] % 58);
  config.crc_bits = 6;
  config.store_debug = (data[2] & 1) != 0;

  // Exact-size heap copy so ASan sees any read past the sample buffer.
  std::vector<uint8_t> buffer(data + 3, data + size);
  const auto result = moteus::ExtractBisscFrame(
      buffer.data(), static_cast<uint32_t>(buffer.size()), config);
  volatile uint64_t sink = result.data_value + static_cast<int>(result.error);
  (void)sink;
  return 0;
}
