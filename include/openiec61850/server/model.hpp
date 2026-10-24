#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

// basic_type.hpp first (see the note in model/quality.hpp about -Wshadow).
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/core/result.hpp"
#include "openiec61850/mms/data.hpp"
#include "openiec61850/mms/type_description.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/server/error.hpp"

// The server's IED data model (IEC 61850-7-2 §6 - §9): logical devices, logical nodes, data
// objects (with sub-data objects), data attributes (with sub-attributes), data sets and report
// control blocks, and its MMS view (IEC 61850-8-1 §8 - §9):
//
//   LD                     -> MMS domain
//   LN                     -> named variable "LN", a structure with one component per FC
//                             present in the LN, in the order ST MX SP SV CF DC SG SE SR OR BL EX
//                             CO US MS RP BR LG GO GS
//   LN, FC                 -> "LN$FC", a structure of the DOs (and control blocks) having data
//                             attributes with that FC, in model order
//   DO / SDO / DA / BDA    -> "LN$FC$DO$SDO$DA$BDA"
//   data set LD/LN.DS      -> domain-specific named variable list "LN$DS"
//
// The model is built once with model_builder (programmatically or from SCL) and is immutable
// afterwards: the server copies the initial values and owns the live ones.
//
// Arrays (attribute_options::count) hold their whole value at the array attribute; elements are
// addressed with an index (MMS AlternateAccess) and are not separate nodes. Their sub-attributes,
// when the element is a structure, are a template describing the element type.

namespace openiec61850::server {

using node_id = std::uint32_t;
inline constexpr node_id no_node = std::numeric_limits<node_id>::max();

enum class node_kind : std::uint8_t {
  logical_device,
  logical_node,
  data_object,     // DO or SDO
  control_block,   // a report control block (its attributes are data attributes)
  data_attribute,  // DA or BDA
};

// SCL TrgOps of a data attribute (dchg / qchg / dupd).
struct trigger_options {
  bool dchg = false;
  bool qchg = false;
  bool dupd = false;

  friend constexpr bool operator==(trigger_options, trigger_options) noexcept = default;
};

inline constexpr trigger_options on_dchg{true, false, false};
inline constexpr trigger_options on_qchg{false, true, false};
inline constexpr trigger_options on_dupd{false, false, true};

struct node {
  std::string name;
  node_kind kind = node_kind::data_attribute;
  node_id parent = no_node;
  std::vector<node_id> children;
  // Data attributes (inherited by sub-attributes) and the attributes of control blocks.
  std::optional<model::functional_constraint> fc;
  // Leaf attributes: the basic type and its size (string length, bit count of CODED ENUM /
  // PACKED LIST). Unset for a constructed attribute.
  std::optional<model::basic_type> type;
  std::int32_t size = 0;
  std::uint32_t count = 0;  // > 0: an array of `count` elements
  trigger_options triggers;
  // Leaf or array attributes: the initial value.
  mms::data value;
  // Bit i set when the subtree holds a data attribute with functional_constraint(i).
  std::uint32_t fc_mask = 0;

  [[nodiscard]] bool is_attribute() const noexcept { return kind == node_kind::data_attribute; }
  // Leaves and arrays store a value; constructed attributes and objects do not.
  [[nodiscard]] bool holds_value() const noexcept {
    return kind == node_kind::data_attribute && (count > 0 || type.has_value());
  }
  [[nodiscard]] bool has_fc(model::functional_constraint f) const noexcept {
    return (fc_mask & (1U << static_cast<unsigned>(f))) != 0;
  }
};

// A data set defined by the model (persistent, not deletable).
struct data_set_definition {
  node_id ln = no_node;
  std::string name;
  // FCD / FCDA references (IEC 61850-7-2 §13.2).
  std::vector<model::object_reference> members;
};

// A BRCB or URCB defined by the model (IEC 61850-7-2 §17.2, SCL ReportControl). One definition per
// instance: an SCL ReportControl with RptEnabled max="3" indexed="true" yields three of them.
struct report_control_settings {
  std::string name;
  bool buffered = false;
  std::string rpt_id;
  // Name of a data set of the same LN; empty: none.
  std::string data_set;
  std::uint32_t conf_rev = 1;
  model::optional_fields opt_flds;
  std::uint32_t buf_tm = 0;
  model::trigger_conditions trg_ops;
  std::uint32_t intg_pd = 0;
};

struct report_control_definition {
  node_id ln = no_node;
  node_id node = no_node;  // the control block node (FC BR or RP)
  report_control_settings settings;
};

class model_builder;
class ln_handle;
class do_handle;
class da_handle;

// The immutable model. Movable; nodes are addressed by node_id.
class data_model {
 public:
  data_model() = default;

  [[nodiscard]] model::edition edition() const noexcept { return edition_; }
  [[nodiscard]] std::span<const node> nodes() const noexcept { return nodes_; }
  [[nodiscard]] const node& at(node_id id) const noexcept { return nodes_[id]; }
  [[nodiscard]] std::span<const node_id> logical_devices() const noexcept { return lds_; }
  [[nodiscard]] std::span<const data_set_definition> data_sets() const noexcept { return data_sets_; }
  [[nodiscard]] std::span<const report_control_definition> report_controls() const noexcept {
    return rcbs_;
  }

  [[nodiscard]] node_id find_logical_device(std::string_view name) const noexcept;
  [[nodiscard]] node_id find_child(node_id parent, std::string_view name) const noexcept;
  // The node named by an object reference: LD, LN, DO, control block or DA. With an FC, only
  // attributes with that FC are considered below the LN (a DO matches when it has some). Array
  // indices are not nodes: a reference with an index fails (errc::object_not_found).
  [[nodiscard]] result<node_id> find(const model::object_reference& ref) const;

  // The ACSI reference "LD/LN.DO.DA" of a node.
  [[nodiscard]] std::string reference_of(node_id id) const;
  // The logical node / device containing a node (the node itself when it is one); no_node above.
  [[nodiscard]] node_id logical_node_of(node_id id) const noexcept;
  [[nodiscard]] node_id logical_device_of(node_id id) const noexcept;

  // The MMS TypeDescription of a node seen under `fc` (8-1 §8.1.3): for an LN without an FC the
  // structure of its FCs; for an LN with an FC, a DO or a control block, the structure of the
  // components having that FC; for an attribute its type (`fc` is then ignored).
  [[nodiscard]] result<mms::type_description> type_of(
      node_id id, std::optional<model::functional_constraint> fc = std::nullopt) const;

 private:
  friend class model_builder;
  friend class ln_handle;
  friend class do_handle;
  friend class da_handle;

  model::edition edition_ = model::edition::ed2;
  std::vector<node> nodes_;
  std::vector<node_id> lds_;
  std::vector<data_set_definition> data_sets_;
  std::vector<report_control_definition> rcbs_;
};

// Options of a data attribute.
struct attribute_options {
  trigger_options triggers;
  // Maximum length of a string type, bit count of CODED ENUM / PACKED LIST; ignored otherwise.
  std::int32_t size = 0;
  // > 0: an array of `count` elements of the attribute type.
  std::uint32_t count = 0;
  // Initial value; unset: the default of the type (false, 0, empty string, zero bits, epoch).
  std::optional<mms::data> value;

  attribute_options& with_triggers(trigger_options t) noexcept {
    triggers = t;
    return *this;
  }
  attribute_options& with_size(std::int32_t s) noexcept {
    size = s;
    return *this;
  }
  attribute_options& with_count(std::uint32_t n) noexcept {
    count = n;
    return *this;
  }
  attribute_options& with_value(mms::data v) {
    value = std::move(v);
    return *this;
  }
};

class ln_handle;
class do_handle;
class da_handle;

// Handles returned by the builder. They stay valid while the builder exists. After an error
// (recorded by the builder and returned by build()) the handles returned are inert.
class ld_handle {
 public:
  ln_handle logical_node(std::string_view name);
  [[nodiscard]] node_id id() const noexcept { return id_; }

 private:
  friend class model_builder;
  ld_handle(model_builder* b, node_id id) noexcept : b_(b), id_(id) {}
  model_builder* b_;
  node_id id_;
};

class ln_handle {
 public:
  do_handle data_object(std::string_view name);
  // A persistent data set of this LN; members are FCD/FCDA references (checked by build()).
  ln_handle& data_set(std::string_view name, std::vector<model::object_reference> members);
  // A report control block of this LN, with its attributes (FC BR or RP).
  ln_handle& report_control(report_control_settings settings);
  [[nodiscard]] node_id id() const noexcept { return id_; }

 private:
  friend class model_builder;
  friend class ld_handle;
  ln_handle(model_builder* b, node_id id) noexcept : b_(b), id_(id) {}
  model_builder* b_;
  node_id id_;
};

class do_handle {
 public:
  do_handle sub_object(std::string_view name);
  // A leaf data attribute.
  da_handle attribute(std::string_view name, model::functional_constraint fc,
                      model::basic_type type, attribute_options options = {});
  // A constructed data attribute; add its sub-attributes to the returned handle.
  da_handle structure(std::string_view name, model::functional_constraint fc,
                      attribute_options options = {});
  [[nodiscard]] node_id id() const noexcept { return id_; }

 private:
  friend class ln_handle;
  friend class model_builder;
  do_handle(model_builder* b, node_id id) noexcept : b_(b), id_(id) {}
  model_builder* b_;
  node_id id_;
};

class da_handle {
 public:
  // Sub-attributes of a constructed attribute; they inherit its FC.
  da_handle attribute(std::string_view name, model::basic_type type, attribute_options options = {});
  da_handle structure(std::string_view name, attribute_options options = {});
  // Sets the initial value of a leaf or array attribute (checked by build()).
  da_handle& value(mms::data v);
  [[nodiscard]] node_id id() const noexcept { return id_; }

 private:
  friend class do_handle;
  friend class model_builder;
  da_handle(model_builder* b, node_id id) noexcept : b_(b), id_(id) {}
  model_builder* b_;
  node_id id_;
};

// Builds a data_model. Usage:
//
//   model_builder b;
//   auto ln = b.logical_device("IED1LD0").logical_node("GGIO1");
//   auto ind = ln.data_object("Ind1");
//   ind.attribute("stVal", fc::ST, basic_type::boolean, attribute_options{}.with_triggers(on_dchg));
//   ind.attribute("q", fc::ST, basic_type::quality, attribute_options{}.with_triggers(on_qchg));
//   ind.attribute("t", fc::ST, basic_type::timestamp);
//   ln.data_set("DS1", {*object_reference::parse("IED1LD0/GGIO1.Ind1[ST]")});
//   report_control_settings rc;
//   rc.name = "urcb01";
//   rc.data_set = "DS1";
//   ln.report_control(rc);
//   auto model = b.build();
//
// An SCL loader drives the same calls with the instantiated tree (LD/LN/DO/SDO/DA/BDA, FC, bType,
// count, Val, dchg/qchg/dupd), the DataSets and the ReportControl instances. The first error
// (invalid or duplicate name, misuse of a handle) is recorded and returned by build(), which also
// checks the values, the data set members and the control blocks' data sets.
class model_builder {
 public:
  explicit model_builder(model::edition edition = model::edition::ed2);
  // Handles point to the builder, so it is neither copied nor moved.
  model_builder(const model_builder&) = delete;
  model_builder& operator=(const model_builder&) = delete;

  ld_handle logical_device(std::string_view name);
  // Handles for nodes created earlier (e.g. by id when walking an SCL tree).
  [[nodiscard]] ln_handle logical_node_handle(node_id id) noexcept { return {this, id}; }
  [[nodiscard]] do_handle data_object_handle(node_id id) noexcept { return {this, id}; }
  [[nodiscard]] da_handle attribute_handle(node_id id) noexcept { return {this, id}; }

  // The first error recorded so far (empty when none).
  [[nodiscard]] std::error_code error() const noexcept { return error_; }

  // Validates and returns the model; the builder is left empty.
  [[nodiscard]] result<data_model> build();

 private:
  friend class ld_handle;
  friend class ln_handle;
  friend class do_handle;
  friend class da_handle;

  node_id add(node_id parent, std::string_view name, node_kind kind);
  void fail(std::error_code ec) noexcept {
    if (!error_) error_ = ec;
  }
  [[nodiscard]] bool usable(node_id id, node_kind kind) const noexcept;
  node_id add_attribute(node_id parent, std::string_view name,
                        std::optional<model::functional_constraint> fc,
                        std::optional<model::basic_type> type, attribute_options options);
  void add_report_control(node_id ln, report_control_settings settings);

  data_model m_;
  std::error_code error_;
};

// The default value of a basic type (with `count` > 0, an array of defaults).
[[nodiscard]] result<mms::data> default_value(model::basic_type type, std::int32_t size = 0,
                                              std::uint32_t count = 0,
                                              model::edition e = model::edition::ed2);

// Parses the text form of a value as found in SCL Val elements: "true"/"false"/"1"/"0" for
// BOOLEAN, decimal integers (ENUMERATED: the ordinal), floats, strings as is, bit strings as '0'/'1'
// digits (bit 0 first) or, for Dbpos/Tcmd, "intermediate-state"/"off"/"on"/"bad-state" and
// "stop"/"lower"/"higher"/"reserved", EntryID / OCTET STRING as hex digits. TimeStamp and
// EntryTime are not parsed (errc::unsupported). errc::type_mismatch for an unparsable text.
[[nodiscard]] result<mms::data> parse_value(model::basic_type type, std::string_view text,
                                            std::int32_t size = 0);

}  // namespace openiec61850::server
