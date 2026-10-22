#include "openiec61850/association/types.hpp"

#include <algorithm>

#include "openiec61850/association/client_association.hpp"
#include "openiec61850/association/server_association.hpp"

namespace openiec61850::association {

result<received_pdu> received_pdu::decode(std::shared_ptr<const byte_buffer> buffer,
                                          byte_view encoding, const mms::decode_options& opts) {
  auto pdu = mms::decode_pdu(encoding, opts);
  if (!pdu) return pdu.error();
  received_pdu r;
  r.buffer_ = std::move(buffer);
  r.encoding_ = encoding;
  r.pdu_ = std::move(*pdu);
  return r;
}

service_error_info service_error_info::from(const mms::service_error& e) {
  service_error_info i;
  i.cls = e.cls;
  i.code = e.code;
  i.additional_code = e.additional_code;
  if (e.additional_description) i.additional_description = std::string(*e.additional_description);
  i.service_specific_info.assign(e.service_specific_info.begin(), e.service_specific_info.end());
  return i;
}

mms::service_error service_error_info::view() const noexcept {
  mms::service_error e(cls, code);
  e.additional_code = additional_code;
  if (additional_description) e.additional_description = std::string_view(*additional_description);
  e.service_specific_info = service_specific_info;
  return e;
}

transport::channel_options default_channel_options() {
  transport::channel_options o;
  o.cotp.calling_tsap = byte_buffer{0x00, 0x01};
  o.cotp.called_tsap = byte_buffer{0x00, 0x01};
  return o;
}

mms::initiate_response negotiate(const mms::initiate_request& proposed,
                                 const mms::initiate_response& local) noexcept {
  mms::initiate_response r = local;
  auto lower = [](std::int16_t p, std::int16_t l) {
    return std::max<std::int16_t>(1, std::min(p, l));
  };
  r.max_serv_outstanding_calling =
      lower(proposed.max_serv_outstanding_calling, local.max_serv_outstanding_calling);
  r.max_serv_outstanding_called =
      lower(proposed.max_serv_outstanding_called, local.max_serv_outstanding_called);
  if (!proposed.data_structure_nesting_level) {
    r.data_structure_nesting_level.reset();
  } else if (local.data_structure_nesting_level) {
    r.data_structure_nesting_level =
        std::min(*proposed.data_structure_nesting_level, *local.data_structure_nesting_level);
  } else {
    r.data_structure_nesting_level = proposed.data_structure_nesting_level;
  }
  r.detail.version_number = std::min(proposed.detail.version_number, local.detail.version_number);
  r.detail.parameter_cbb = proposed.detail.parameter_cbb.intersect(local.detail.parameter_cbb);
  r.detail.services = local.detail.services;
  return r;
}

}  // namespace openiec61850::association
