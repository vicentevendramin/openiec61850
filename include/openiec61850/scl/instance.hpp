#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "openiec61850/core/result.hpp"
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/rcb_options.hpp"
#include "openiec61850/scl/btype.hpp"
#include "openiec61850/scl/diagnostics.hpp"
#include "openiec61850/scl/document.hpp"

// The instantiated data model of one IED server: the LNodeType / DOType / DAType templates
// expanded under every LD and LN, with initial values from the templates (DA/BDA <Val>) overridden
// by the instance (DOI / SDI / DAI), and the FCDAs of data sets resolved to object references.
//
// The tree is plain data meant to be mapped by a server model builder:
//   instantiated_ied -> instantiated_ld -> instantiated_ln -> data_node (DO)
//     -> data_node (SDO or DA) -> data_node (BDA) ...
// Children keep the declaration order of the templates (SDOs and DAs interleaved as declared);
// grouping by FC for the MMS mapping (IEC 61850-8-1 §7.3) is left to the consumer.
// Arrays (count > 0) are not expanded: the node describes one element, `count` the size, and
// values of individual elements carry an index. A DAI below a DOI / SDI with ix, which addresses
// one element of an array of data objects, carries that ix in `objects`.

namespace openiec61850::scl {

enum class node_kind : std::uint8_t { data_object, data_attribute };

struct initial_value {
  std::string text;
  scalar parsed;  // monostate when the text could not be converted (a warning was reported)
  std::optional<std::uint32_t> sgroup;
  std::optional<std::uint32_t> index;  // array element (DAI ix)
  // The element of each enclosing array of data objects, outermost first; nullopt or a missing
  // entry: every element.
  std::vector<std::optional<std::uint32_t>> objects;
};

struct data_node {
  node_kind kind = node_kind::data_object;
  std::string name;
  std::string desc;
  std::string type_id;      // DOType (DO/SDO), DAType (Struct) or EnumType (Enum) id
  std::uint32_t count = 0;  // array size; 0 = not an array

  // Data objects.
  std::string cdc;

  // Data attributes (DA and BDA); BDAs inherit fc and trigger options from their DA.
  std::optional<model::functional_constraint> fc;
  std::string btype;
  std::optional<model::basic_type> type;  // nullopt for Struct and unmapped bTypes
  std::uint32_t size = 0;                 // maximum length of string types
  model::trigger_conditions triggers;     // dchg / qchg / dupd
  value_kind kind_of_value = value_kind::set;
  std::string short_addr;
  std::vector<initial_value> values;

  std::vector<data_node> children;

  [[nodiscard]] bool is_data_object() const noexcept { return kind == node_kind::data_object; }
  [[nodiscard]] bool is_struct() const noexcept {
    return kind == node_kind::data_attribute && !type.has_value() && !children.empty();
  }
  [[nodiscard]] const data_node* child(std::string_view n) const noexcept;
  // True when this node is an attribute with `f` or has such an attribute below it.
  [[nodiscard]] bool has_fc(model::functional_constraint f) const noexcept;
};

struct resolved_data_set {
  std::string name;
  std::string desc;
  std::vector<model::object_reference> members;  // functionally constrained (FCD / FCDA)
};

struct instantiated_ln {
  std::string name;  // prefix + lnClass + inst
  std::string prefix;
  std::string ln_class;
  std::string inst;
  std::string ln_type;
  std::string desc;
  std::vector<data_node> data_objects;
  std::vector<resolved_data_set> data_sets;
  std::vector<report_control> report_controls;
  std::vector<log_control> log_controls;
  std::vector<gse_control> gse_controls;
  std::vector<sampled_value_control> smv_controls;
  std::optional<setting_control> setting;

  [[nodiscard]] const data_node* find(std::string_view do_name) const noexcept;
  [[nodiscard]] const resolved_data_set* find_data_set(std::string_view n) const noexcept;
};

struct instantiated_ld {
  std::string name;  // ldName or IED name + inst
  std::string inst;
  std::string desc;
  std::vector<instantiated_ln> lns;  // LLN0 first

  [[nodiscard]] const instantiated_ln* find(std::string_view ln_name) const noexcept;
};

struct instantiated_ied {
  std::string name;
  std::string access_point;
  model::edition edition = model::edition::ed2;
  std::vector<instantiated_ld> lds;
  std::vector<enum_type> enum_types;  // the EnumTypes used by the tree

  [[nodiscard]] const instantiated_ld* find(std::string_view ld_name) const noexcept;
  [[nodiscard]] const enum_type* find_enum_type(std::string_view id) const noexcept;
  // The node at `ref` (LD/LN.DO[.SDO][.DA][.BDA], array indexes allowed). When `ref` has an FC,
  // the node must be an attribute with that FC or a data object having such attributes.
  [[nodiscard]] const data_node* find(const model::object_reference& ref) const noexcept;
  [[nodiscard]] std::size_t node_count() const noexcept;
};

struct instantiate_options {
  // Any error-level diagnostic fails the instantiation with errc::malformed_encoding.
  bool strict = false;
  // Total data_node count; exceeding it fails with errc::length_overflow.
  std::size_t max_nodes = 1'000'000;
  // Nesting of SDOs / BDAs.
  std::size_t max_depth = 32;
};

// Instantiates the server of `access_point` of IED `ied_name` (the first access point with a
// server when empty; ServerAt is followed). Fails with errc::invalid_state when the IED, access
// point or server does not exist. Problems are appended to `diags` when given; in lenient mode
// unresolvable LNs, DOs and attributes are dropped and unresolved DOI/DAI and FCDAs skipped.
[[nodiscard]] result<instantiated_ied> instantiate(const document& doc, std::string_view ied_name,
                                                   std::string_view access_point = {},
                                                   diagnostics* diags = nullptr,
                                                   const instantiate_options& opts = {});

// Builds the functionally constrained reference of an FCDA of IED `ied_name`:
// LD (the LD of ldInst in that IED's server, by ldName or IED name + inst) / prefix lnClass lnInst
// . doName [. daName] [(ix)] [FC]. Fails with errc::malformed_encoding when the parts do not form
// a valid reference and errc::invalid_state when the IED or LD does not exist. Name limits follow
// the document edition.
[[nodiscard]] result<model::object_reference> resolve_fcda(const document& doc,
                                                           std::string_view ied_name,
                                                           const fcda& member);
// Same, with the LD name already known.
[[nodiscard]] result<model::object_reference> make_fcda_reference(
    std::string_view ld_name, const fcda& member,
    const model::parse_options& opts = model::parse_options{});

}  // namespace openiec61850::scl
