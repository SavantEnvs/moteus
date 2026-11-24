// Fuzz the moteus C++ client's CAN-FD reply decoding (lib/cpp/mjbots/moteus/moteus_protocol.h):
// a reply frame from a controller is parsed by Query::Parse (register reply subframes, varuint,
// int8/16/32/float scaling), GenericQuery::Parse, and the diagnostic-channel response parsers.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "moteus_protocol.h"

using namespace mjbots::moteus;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // A CAN-FD frame carries at most 64 data bytes; the API takes a uint8_t size
  // (CanData::data is uint8_t[64]).
  if (size > 64) { return -1; }
  const uint8_t n = static_cast<uint8_t>(size);

  volatile double sink = 0;
  {
    const auto r = Query::Parse(data, n);
    sink = sink + r.position + r.velocity + r.torque + static_cast<int>(r.mode);
  }
  {
    const auto r = GenericQuery::Parse(data, n);
    (void)r;
  }
  {
    CanData frame;
    std::memcpy(frame.data, data, n);
    frame.size = n;
    const auto r = Query::Parse(&frame);
    sink = sink + r.voltage + r.temperature;
  }
  {
    const auto r = DiagnosticResponse::Parse(data, n);
    sink = sink + r.size + r.channel;
  }
  {
    const auto r = DiagnosticFlowResponse::Parse(data, n);
    sink = sink + r.size + r.packet_number;
  }
  (void)sink;
  return 0;
}
