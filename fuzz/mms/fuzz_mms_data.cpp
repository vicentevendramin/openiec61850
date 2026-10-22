// Parses arbitrary input as one MMS Data value and walks it with data_view (see fuzz_util.hpp),
// and as a TypeDescription, which must re-encode to a fixed point.
// Seed corpus: fuzz/corpus/mms_data/

#include <cstddef>
#include <cstdint>

#include "fuzz_util.hpp"
#include "openiec61850/mms/type_description.hpp"

namespace mms = openiec61850::mms;
using openiec61850::byte_buffer;
using openiec61850::byte_view;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const byte_view input{data, size};
  if (auto v = mms::data_view::parse(input)) mms_fuzz::walk(*v);
  (void)mms::data_view::parse(input, {.max_nesting = 2});

  if (auto t = mms::type_description::decode(input)) {
    byte_buffer first;
    openiec61850::ber::writer w1{first};
    mms_fuzz::check(static_cast<bool>(t->encode(w1)));
    auto back = mms::type_description::decode(first, {.max_nesting = 1024});
    mms_fuzz::check(back.has_value() && *back == *t);
  }
  return 0;
}
