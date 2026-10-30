#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// basic_type.hpp must come before rcb_options.hpp (see the note there).
#include "openiec61850/model/basic_type.hpp"
#include "openiec61850/model/functional_constraint.hpp"
#include "openiec61850/model/object_reference.hpp"
#include "openiec61850/model/rcb_options.hpp"

// Owning document model of an SCL file (IEC 61850-6): SCL / Header / Communication / IED /
// DataTypeTemplates, as written in the file. Names and references are kept as text; nothing is
// resolved here (see instance.hpp). Every element records the 1-based line where it starts
// (0 when unknown). Absent optional attributes take the schema defaults noted below.

namespace openiec61850::scl {

// valKind (IEC 61850-6 §9.5.4.3).
enum class value_kind : std::uint8_t { spec, conf, ro, set };

[[nodiscard]] std::string_view to_string(value_kind k) noexcept;
[[nodiscard]] std::optional<value_kind> parse_value_kind(std::string_view text) noexcept;

// <Val>; sGroup is set for setting-group values (FC SG/SE).
struct value {
  std::string text;
  std::optional<std::uint32_t> sgroup;
};

struct header {
  std::string id;
  std::string version;
  std::string revision;
  std::string tool_id;
  std::string name_structure = "IEDName";
  std::uint32_t line = 0;
};

// ------------------------------------------------------------------ Communication

// <P type="IP">10.0.0.1</P>
struct p_address {
  std::string type;
  std::string value;
};

struct address {
  std::vector<p_address> p;
  // Value of the first P of `type`, or nullptr.
  [[nodiscard]] const std::string* find(std::string_view type) const noexcept;
};

// <GSE ldInst cbName> with MinTime / MaxTime in ms.
struct gse_address {
  std::string ld_inst;
  std::string cb_name;
  struct address addr;
  std::optional<std::uint32_t> min_time;
  std::optional<std::uint32_t> max_time;
  std::uint32_t line = 0;
};

struct smv_address {
  std::string ld_inst;
  std::string cb_name;
  struct address addr;
  std::uint32_t line = 0;
};

struct connected_ap {
  std::string ied_name;
  std::string ap_name;
  std::string desc;
  struct address addr;
  std::vector<gse_address> gse;
  std::vector<smv_address> smv;
  std::uint32_t line = 0;
};

struct sub_network {
  std::string name;
  std::string desc;
  std::string type;  // e.g. "8-MMS"
  std::vector<connected_ap> connected_aps;
  std::uint32_t line = 0;
};

struct communication {
  std::vector<sub_network> sub_networks;
  // The first ConnectedAP of `ied` / `ap` in any subnetwork, or nullptr.
  [[nodiscard]] const connected_ap* find(std::string_view ied, std::string_view ap) const noexcept;
};

// ------------------------------------------------------------------ DataTypeTemplates

struct enum_value {
  std::int32_t ord = 0;
  std::string text;  // may be empty (Ed.2 allows an EnumVal without text)
  std::string desc;
};

struct enum_type {
  std::string id;
  std::string desc;
  std::vector<enum_value> values;
  std::uint32_t line = 0;

  [[nodiscard]] const enum_value* find_text(std::string_view text) const noexcept;
  [[nodiscard]] const enum_value* find_ord(std::int32_t ord) const noexcept;
};

// <DO> of an LNodeType.
struct data_object_def {
  std::string name;
  std::string type;  // DOType id
  std::string desc;
  std::uint32_t count = 0;  // array size; 0 = not an array
  bool transient = false;
  std::uint32_t line = 0;
};

// <SDO> of a DOType.
struct sub_data_object_def {
  std::string name;
  std::string type;  // DOType id
  std::string desc;
  std::uint32_t count = 0;  // array size (Ed.2.1); 0 = not an array
  std::uint32_t position = 0;  // declaration order among the SDOs and DAs of the DOType
  std::uint32_t line = 0;
};

// <DA> of a DOType or <BDA> of a DAType (the latter has no fc and no trigger options).
struct attribute_def {
  std::string name;
  std::string desc;
  std::optional<model::functional_constraint> fc;  // DA only; required there
  bool dchg = false;
  bool qchg = false;
  bool dupd = false;
  std::string btype;        // e.g. "FLOAT32", "Enum", "Struct", "VisString255"
  std::string type;         // DAType id (Struct) or EnumType id (Enum)
  std::uint32_t count = 0;  // array size; 0 = not an array
  value_kind kind = value_kind::set;
  bool val_import = false;
  std::vector<value> values;
  std::string s_addr;
  std::uint32_t position = 0;  // declaration order among the SDOs and DAs of the DOType
  std::uint32_t line = 0;
};

struct lnode_type {
  std::string id;
  std::string ln_class;
  std::string desc;
  std::string ied_type;
  std::vector<data_object_def> data_objects;
  std::uint32_t line = 0;
};

struct do_type {
  std::string id;
  std::string cdc;
  std::string desc;
  std::string ied_type;
  std::vector<sub_data_object_def> sub_data_objects;
  std::vector<attribute_def> attributes;
  std::uint32_t line = 0;
};

struct da_type {
  std::string id;
  std::string desc;
  std::string ied_type;
  std::vector<attribute_def> attributes;  // BDAs
  std::uint32_t line = 0;
};

struct data_type_templates {
  std::vector<lnode_type> lnode_types;
  std::vector<do_type> do_types;
  std::vector<da_type> da_types;
  std::vector<enum_type> enum_types;

  // Linear searches; instantiate() indexes the templates itself.
  [[nodiscard]] const lnode_type* find_lnode_type(std::string_view id) const noexcept;
  [[nodiscard]] const do_type* find_do_type(std::string_view id) const noexcept;
  [[nodiscard]] const da_type* find_da_type(std::string_view id) const noexcept;
  [[nodiscard]] const enum_type* find_enum_type(std::string_view id) const noexcept;
};

// ------------------------------------------------------------------ IED

// <FCDA>; doName and daName may contain '.'-separated sub-names.
struct fcda {
  std::string ld_inst;
  std::string prefix;
  std::string ln_class;
  std::string ln_inst;
  std::string do_name;
  std::string da_name;
  std::optional<model::functional_constraint> fc;
  std::optional<std::uint32_t> ix;  // array index (Ed.2), applied to the last name
  std::uint32_t line = 0;
};

struct data_set {
  std::string name;
  std::string desc;
  std::vector<fcda> members;
  std::uint32_t line = 0;
};

// <ClientLN> of RptEnabled.
struct client_ln {
  std::string ied_name;
  std::string ld_inst;
  std::string prefix;
  std::string ln_class;
  std::string ln_inst;
  std::string ap_ref;
  std::uint32_t line = 0;
};

// <ReportControl>. Defaults per the SCL schema: buffered false, indexed true, TrgOps gi true,
// OptFields bufOvfl true, RptEnabled max 1.
struct report_control {
  std::string name;
  std::string desc;
  std::string dat_set;
  std::string rpt_id;
  std::uint32_t conf_rev = 0;
  bool buffered = false;
  std::uint32_t buf_time = 0;  // ms
  std::uint32_t intg_pd = 0;   // ms
  bool indexed = true;
  model::trigger_conditions trg_ops =
      model::trigger_conditions::of({model::trigger::general_interrogation});
  model::optional_fields opt_fields =
      model::optional_fields::of({model::optional_field::buffer_overflow});
  std::uint32_t rpt_enabled_max = 1;
  bool has_rpt_enabled = false;
  std::vector<client_ln> clients;
  std::uint32_t line = 0;
};

struct gse_control {
  std::string name;
  std::string desc;
  std::string dat_set;
  std::string app_id;  // GoID
  std::uint32_t conf_rev = 0;
  std::string type = "GOOSE";  // "GOOSE" or "GSSE"
  bool fixed_offs = false;
  std::uint32_t line = 0;
};

// <SmvOpts>.
struct smv_options {
  bool refresh_time = false;
  bool sample_synchronized = true;
  bool sample_rate = false;
  bool data_set = false;
  bool security = false;
  bool timestamp = false;
  bool synch_source_id = false;
};

struct sampled_value_control {
  std::string name;
  std::string desc;
  std::string dat_set;
  std::string smv_id;
  std::uint32_t conf_rev = 0;
  std::uint32_t smp_rate = 0;
  std::uint32_t nof_asdu = 0;
  std::string smp_mod = "SmpPerPeriod";
  bool multicast = true;
  smv_options opts;
  std::uint32_t line = 0;
};

struct log_control {
  std::string name;
  std::string desc;
  std::string dat_set;
  std::string log_name;
  bool log_ena = true;
  bool reason_code = true;
  std::uint32_t buf_time = 0;
  std::uint32_t intg_pd = 0;
  model::trigger_conditions trg_ops =
      model::trigger_conditions::of({model::trigger::general_interrogation});
  std::string ld_inst;
  std::string prefix;
  std::string ln_class = "LLN0";
  std::string ln_inst;
  std::uint32_t line = 0;
};

struct setting_control {
  std::string desc;
  std::uint32_t num_of_sgs = 0;
  std::uint32_t act_sg = 1;
  std::uint32_t line = 0;
};

// <DAI>.
struct attribute_instance {
  std::string name;
  std::string desc;
  std::string s_addr;
  std::optional<value_kind> kind;
  std::optional<std::uint32_t> ix;  // array element
  std::vector<value> values;
  std::uint32_t line = 0;
};

// <DOI> or <SDI> (an SDI may address a sub-data object or a structured attribute).
struct data_instance {
  std::string name;
  std::string desc;
  std::string s_addr;  // SDI only
  std::optional<std::uint32_t> ix;
  std::vector<data_instance> sub_instances;
  std::vector<attribute_instance> attributes;
  std::uint32_t line = 0;
};

// <LN0> or <LN>. GSE/SMV controls and SettingControl appear in LN0 only.
struct logical_node {
  std::string prefix;
  std::string ln_class;
  std::string inst;
  std::string ln_type;
  std::string desc;
  std::vector<data_set> data_sets;
  std::vector<report_control> report_controls;
  std::vector<log_control> log_controls;
  std::vector<gse_control> gse_controls;
  std::vector<sampled_value_control> smv_controls;
  std::optional<setting_control> setting;
  std::vector<data_instance> data;  // DOIs
  std::uint32_t line = 0;

  // prefix + lnClass + inst, e.g. "LLN0", "MMXU1", "QA1XCBR1".
  [[nodiscard]] std::string name() const;
  [[nodiscard]] const data_set* find_data_set(std::string_view n) const noexcept;
};

struct logical_device {
  std::string inst;
  std::string ld_name;  // Ed.2 ldName; empty when absent
  std::string desc;
  logical_node ln0;
  std::vector<logical_node> lns;
  std::uint32_t line = 0;

  // The LD name used in object references: ldName, or IED name + inst (IEC 61850-6 §8.5.3).
  [[nodiscard]] std::string name(std::string_view ied_name) const;
  // Searches LN0 and the LNs by prefix + lnClass + inst.
  [[nodiscard]] const logical_node* find_ln(std::string_view ln_name) const;
};

struct authentication {
  bool none = true;
  bool password = false;
  bool weak = false;
  bool strong = false;
  bool certificate = false;
};

struct server {
  std::uint32_t timeout = 30;  // s
  struct authentication auth;
  std::vector<logical_device> ldevices;
  std::uint32_t line = 0;

  [[nodiscard]] const logical_device* find_ld(std::string_view inst) const noexcept;
};

struct access_point {
  std::string name;
  std::string desc;
  bool router = false;
  bool clock = false;
  std::optional<struct server> srv;
  std::string server_at;  // Ed.2 <ServerAt apName>: the server is the one of that access point
  std::uint32_t line = 0;
};

// One element of <Services>, kept generically: e.g. {"ConfDataSet", {{"max","10"},...}, {}} or
// {"ReportSettings", {{"cbName","Conf"}, ...}}. Nested elements (e.g. ClientServices/TimeSyncProt,
// SupSubscription) appear as children.
struct service_capability {
  std::string name;
  std::vector<std::pair<std::string, std::string>> attributes;
  std::vector<service_capability> children;
  std::uint32_t line = 0;

  [[nodiscard]] const std::string* attribute(std::string_view n) const noexcept;
  [[nodiscard]] const service_capability* find(std::string_view n) const noexcept;
  // The "max" attribute as an integer (nullopt when absent or invalid).
  [[nodiscard]] std::optional<std::uint32_t> max() const noexcept;
};

struct services {
  bool present = false;  // the IED has a <Services> element
  std::vector<service_capability> items;

  [[nodiscard]] const service_capability* find(std::string_view n) const noexcept;
  [[nodiscard]] bool has(std::string_view n) const noexcept { return find(n) != nullptr; }
};

struct ied {
  std::string name;
  std::string desc;
  std::string type;
  std::string manufacturer;
  std::string config_version;
  std::string original_scl_version;
  std::string original_scl_revision;
  std::string eng_right;
  std::string owner;
  struct services svc;
  std::vector<access_point> access_points;
  std::uint32_t line = 0;

  [[nodiscard]] const access_point* find_access_point(std::string_view n) const noexcept;
  // The server of access point `ap` (following ServerAt), or of the first access point with a
  // server when `ap` is empty. nullptr when none.
  [[nodiscard]] const struct server* find_server(std::string_view ap = {}) const noexcept;
};

// ------------------------------------------------------------------ SCL

struct document {
  // Ed.1: no version attribute on <SCL>; Ed.2: version="2007" revision="A"; Ed.2.1: revision "B".
  model::edition edition = model::edition::ed2;
  std::string version;
  std::string revision;
  std::optional<std::uint32_t> release;
  struct header hdr;
  struct communication comm;
  std::vector<ied> ieds;
  data_type_templates templates;

  [[nodiscard]] const struct ied* find_ied(std::string_view name) const noexcept;
};

}  // namespace openiec61850::scl
