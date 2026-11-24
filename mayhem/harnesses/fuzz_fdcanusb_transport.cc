// Fuzz the moteus C++ client's fdcanusb / UART serial transport
// (lib/cpp/mjbots/moteus/moteus_transport.h, class Fdcanusb): the bytes a serial device sends
// back ("OK", "ERR ...", "rcv <id> <hex> <flags>", optional "*XX" CRC-8 suffix) are fed through
// the transport's own pipe constructor (the one upstream's unit tests use), during a real Cycle
// that expects a reply. Every decoded reply frame is then decoded with Query::Parse.
//
// First input byte selects the transport options (uart_mode / checksum / brs); the rest is what
// the "device" writes. A fresh transport and fresh pipes are made per input, so no state is kept
// across inputs.
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <future>
#include <vector>

#include "moteus_protocol.h"
#include "moteus_transport.h"

using namespace mjbots::moteus;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size < 1) { return -1; }
  // Keep the device reply under the default pipe capacity (64 KiB) so writing it cannot block.
  if (size > 16384) { return -1; }
  const uint8_t mode = data[0];
  data++;
  size--;

  int to_dut[2];    // device -> transport
  int from_dut[2];  // transport -> device
  if (::pipe(to_dut) != 0) { return 0; }
  if (::pipe(from_dut) != 0) { ::close(to_dut[0]); ::close(to_dut[1]); return 0; }

  {
    Fdcanusb::Options options;
    options.min_ok_wait_ns = 2000000;
    options.min_rcv_wait_ns = 2000000;
    options.rx_extra_wait_ns = 1000000;
    options.final_wait_ns = 50000;
    options.uart_mode = (mode & 1) != 0;
    options.checksum_enabled = (mode & 2) != 0;
    options.disable_brs = (mode & 4) != 0;
    options.max_retries = 0;
    options.auto_detect = false;

    Fdcanusb dut(to_dut[0], from_dut[1], options);

    CanFdFrame frame;
    frame.destination = 1 + ((mode >> 3) & 0x0f);
    frame.source = 0;
    frame.reply_required = true;
    frame.arbitration_id = 0x8000 | frame.destination;
    frame.data[0] = 0x11;
    frame.data[1] = 0x00;
    frame.size = 2;

    std::vector<CanFdFrame> replies;
    std::promise<int> done;
    auto done_future = done.get_future();
    dut.Cycle(&frame, 1, &replies, [&](int err) { done.set_value(err); });

    // Wait until the transport has sent its command (it flushes stale input first), then answer.
    {
      char c = 0;
      while (::read(from_dut[0], &c, 1) == 1 && c != '\n') {}
    }
    size_t off = 0;
    while (off < size) {
      const ssize_t w = ::write(to_dut[1], data + off, size - off);
      if (w <= 0) { break; }
      off += static_cast<size_t>(w);
    }

    done_future.wait();

    volatile double sink = 0;
    for (const auto& reply : replies) {
      const auto r = Query::Parse(reply.data, reply.size);
      sink = sink + r.position + reply.arbitration_id;
    }
    (void)sink;
  }

  ::close(to_dut[0]); ::close(to_dut[1]);
  ::close(from_dut[0]); ::close(from_dut[1]);
  return 0;
}
