// Feeds MMS PDUs to the server's request dispatcher (no network): every confirmed request is
// served against a small model, as if received on one association, and the reply is encoded.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <variant>

#include <asio/io_context.hpp>

#include "../../src/server/detail.hpp"
#include "openiec61850/server/model.hpp"

namespace srv = openiec61850::server;
namespace detail = openiec61850::server::detail;
namespace mms = openiec61850::mms;
namespace model = openiec61850::model;

namespace {

model::object_reference ref(const char* text) { return *model::object_reference::parse(text); }

srv::data_model make_model() {
  using model::basic_type;
  using model::fc;
  srv::model_builder b;
  auto ld = b.logical_device("LD0");
  auto lln0 = ld.logical_node("LLN0");
  lln0.data_object("Mod").attribute("stVal", fc::ST, basic_type::enumerated,
                                    srv::attribute_options{}.with_triggers(srv::on_dchg));
  auto ggio = ld.logical_node("GGIO1");
  auto ind = ggio.data_object("Ind1");
  ind.attribute("stVal", fc::ST, basic_type::boolean, srv::attribute_options{}.with_triggers(srv::on_dchg));
  ind.attribute("q", fc::ST, basic_type::quality, srv::attribute_options{}.with_triggers(srv::on_qchg));
  ind.attribute("t", fc::ST, basic_type::timestamp);
  auto cfg = ggio.data_object("Cfg");
  cfg.structure("s", fc::CF).attribute("v", basic_type::int32u);
  cfg.attribute("arr", fc::SP, basic_type::float32, srv::attribute_options{}.with_count(3));
  auto pos = ggio.data_object("Pos");
  pos.attribute("ctlModel", fc::CF, basic_type::enumerated,
                srv::attribute_options{}.with_value(mms::data::integer(2)));
  pos.attribute("SBO", fc::CO, basic_type::object_reference);
  auto oper = pos.structure("Oper", fc::CO);
  oper.attribute("ctlVal", basic_type::boolean);
  oper.attribute("ctlNum", basic_type::int8u);
  lln0.data_set("DS1", {ref("LD0/GGIO1.Ind1[ST]"), ref("LD0/GGIO1.Cfg.arr(1)[SP]")});
  srv::report_control_settings b1;
  b1.name = "brcb01";
  b1.buffered = true;
  b1.data_set = "DS1";
  b1.trg_ops = model::trigger_conditions::from_raw(0x7E);
  b1.opt_flds = model::optional_fields::from_raw(0x3FE);
  lln0.report_control(b1);
  auto u1 = b1;
  u1.name = "urcb01";
  u1.buffered = false;
  u1.buf_tm = 0;
  lln0.report_control(u1);
  return *b.build();
}

const srv::data_model& shared_model() {
  static const srv::data_model m = make_model();
  return m;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  asio::io_context ctx;
  srv::server_options opts;
  opts.on_control = [](const srv::control_request&) { return srv::control_result::ok(); };
  auto st = detail::make_offline_state(ctx.get_executor(), shared_model(), opts);
  if (!st) return 0;
  detail::session s((*st)->strand);
  s.id = 1;
  s.max_pdu = 1000;
  const openiec61850::byte_view input(data, size);
  auto pdu = mms::decode_pdu(input);
  if (!pdu) return 0;
  const auto* req = std::get_if<mms::confirmed_request>(&*pdu);
  if (req == nullptr) return 0;
  // Twice, so that a second request sees the state changed by the first.
  for (int i = 0; i < 2; ++i) {
    detail::reply out;
    (*st)->dispatch(s, req->service, out);
    if (out.type == detail::reply::kind::response) {
      openiec61850::byte_buffer encoded;
      (void)mms::encode_pdu(mms::confirmed_response{req->invoke_id, out.response}, encoded);
    }
    ctx.poll();
  }
  (*st)->shutdown();
  ctx.poll();
  return 0;
}
