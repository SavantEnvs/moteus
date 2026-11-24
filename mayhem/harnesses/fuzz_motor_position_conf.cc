// fuzz_motor_position_conf: the firmware diagnostic `conf` channel into MotorPosition.
//
// On the device, `conf set <group>.<field> <value>` / `conf get ...` text arrives over the
// diagnostic stream (fdcan diagnostic channel / UART) into mjlib's CommandManager, which hands
// it to PersistentConfig; PersistentConfig parses the value into MotorPosition's config and
// fires MotorPosition::HandleConfigUpdate. The next ISR_Update then runs on that config.
//
// This harness builds the same object graph as fw/test/motor_position_test.cc's Context (mjlib's
// PersistentConfigFixture without its Boost.Test assertions), splits the input into lines and
// writes each allow-listed line (`set ...` / `get ...`) as `conf <line>\n` into the command
// stream, then runs MotorPosition::ISR_Update. Every object is constructed per input, so nothing
// carries over between inputs.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>

#include "fw/motor_position.h"

#include "mjlib/micro/async_exclusive.h"
#include "mjlib/micro/command_manager.h"
#include "mjlib/micro/event_queue.h"
#include "mjlib/micro/flash.h"
#include "mjlib/micro/persistent_config.h"
#include "mjlib/micro/pool_ptr.h"
#include "mjlib/micro/stream_pipe.h"
#include "mjlib/micro/telemetry_manager.h"

using namespace moteus;
namespace micro = mjlib::micro;

namespace {
constexpr float kDt = 0.0001f;

// RAM-backed flash, as mjlib's test StubFlash.
class StubFlash : public micro::FlashInterface {
 public:
  Info GetInfo() override { return {buffer_, buffer_ + sizeof(buffer_)}; }
  void Erase() override { std::memset(buffer_, 0, sizeof(buffer_)); }
  void Unlock() override {}
  void Lock() override {}
  void ProgramByte(char* ptr, uint8_t value) override { *ptr = value; }
  char buffer_[4096] = {};
};

// Drains the response side of the pipe (as mjlib's test Reader), discarding the text.
class Drain {
 public:
  explicit Drain(micro::AsyncReadStream* stream) : stream_(stream) { Start(); }
  void Start() {
    stream_->AsyncReadSome(
        mjlib::base::string_span(buffer_, buffer_ + sizeof(buffer_)),
        [this](micro::error_code ec, std::ptrdiff_t) {
          if (!ec) { Start(); }
        });
  }
  micro::AsyncReadStream* const stream_;
  char buffer_[256] = {};
};

struct Context {
  micro::SizedPool<> pool;
  micro::EventQueue event_queue;
  micro::StreamPipe pipe{event_queue.MakePoster()};
  Drain drain{pipe.side_b()};
  micro::AsyncExclusive<micro::AsyncWriteStream> write_stream{pipe.side_a()};
  micro::CommandManager command_manager{&pool, pipe.side_a(), &write_stream};
  StubFlash flash;
  char output_buffer[4096] = {};
  micro::PersistentConfig persistent_config{
    pool, command_manager, flash, mjlib::base::string_span(output_buffer)};
  micro::TelemetryManager telemetry_manager{
    &pool, &command_manager, &write_stream, output_buffer};
  aux::AuxStatus aux1_status;
  aux::AuxStatus aux2_status;
  aux::AuxConfig aux1_config;
  aux::AuxConfig aux2_config;

  MotorPosition dut{&persistent_config, &telemetry_manager,
                    &aux1_status, &aux2_status,
                    &aux1_config, &aux2_config};

  Context() {
    command_manager.AsyncStart();
    dut.SetRate(kDt);
    dut.motor()->poles = 4;
    dut.config()->sources[0].pll_filter_hz = 400.0 * 2.48;
    persistent_config.Load();
  }

  void Command(const std::string& message) {
    bool done = false;
    micro::AsyncWrite(*pipe.side_b(), message,
                      [&done](micro::error_code) { done = true; });
    // The pipe moves data only through the event queue.
    for (int i = 0; i < 64 && !done; i++) { event_queue.Poll(); }
    event_queue.Poll();
  }
};

// The command manager's line buffer (mjlib CommandManager::Options::max_line_length, default
// 100) must hold `conf ` + line + `\n`; an over-long line is discarded by the command manager
// and would desynchronise the one-command-per-line mapping, so skip it here.
constexpr size_t kMaxLine = 100 - 6;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  auto ctx = std::make_unique<Context>();
  const std::string_view input(reinterpret_cast<const char*>(data), size);

  uint32_t nonce = 0;
  size_t pos = 0;
  while (pos < input.size()) {
    size_t end = input.find('\n', pos);
    if (end == std::string_view::npos) { end = input.size(); }
    std::string_view line = input.substr(pos, end - pos);
    pos = end + 1;
    if (!line.empty() && line.back() == '\r') { line.remove_suffix(1); }
    if (line.size() > kMaxLine) { continue; }
    // Allow-list: only the configuration set/get commands of the `conf` group. The bytes of the
    // line are otherwise passed through unchanged; skip a line with an embedded terminator so one
    // input line stays one command.
    if (line.find('\r') != std::string_view::npos) { continue; }
    if (line.rfind("set ", 0) != 0 && line.rfind("get ", 0) != 0) { continue; }

    ctx->Command("conf " + std::string(line) + "\n");

    // Run the position pipeline on the new config with a live SPI sample.
    ctx->aux1_status.spi.active = true;
    ctx->aux1_status.spi.value = (nonce * 977u) & 0xffffu;
    ctx->aux1_status.spi.nonce = ++nonce;
    ctx->dut.PollMillisecond();
    ctx->dut.ISR_Update();
  }
  return 0;
}
