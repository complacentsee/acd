"""Module (I/O tree) domain of the L5X exporter.

``ModuleBuilder`` decodes a controller's module records (identity, ports,
connections, config image) into ``Module`` elements; the connection maps it
consumes are built by acd.l5x.connections. Split out of elements.py; the
decode logic is unchanged.
"""
import html
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Union

from acd.generated.comps.module_identity import ModuleIdentity
from acd.generated.comps.rx_generic import RxGeneric
from acd.l5x.base import (
    L5xElement,
    L5xElementBuilder,
    own_description,
    safety_signature_row,
    short_own_description,
)
from acd.l5x.catalog_numbers import CATALOG_NUMBERS, CATALOG_NUMBERS_BY_MAJOR
from acd.l5x.connections import (
    _CONFIG_IMG_MAX,
    _CONFIG_MARK,
    _CONFIGSCRIPT_ONLY_PT,
    _CONN_DIRECT_PRODUCT_TYPES,
    _CONN_FMT_OUTPUT,
    _CONN_GENERIC_VENDOR,
    _RACK_COMM_METHOD,
    _config_holder_image,
)
from acd.l5x.port_structures import PORT_STRUCTURES
from acd.l5x import tag_value as _tag_value
from acd.record.comps import CompsRecord


@dataclass
class Module(L5xElement):
    """Represents a Logix hardware module (<Module> in L5X)."""
    name: str
    catalog_number: str
    vendor: int
    product_type: int
    product_code: int
    major: int
    minor: int
    parent_module: str
    parent_mod_port_id: int
    inhibited: str
    major_fault: str
    # Private fields (not serialised as XML attributes)
    # True for the root controller module (parent resolves to itself). Used to
    # special-case the root in port/slot logic; decoupled from major_fault, which
    # is now a real per-module flag and no longer a root proxy.
    _is_root: bool = field(default=False)
    _ekey_state: str = field(default="CompatibleModule")
    _slot: int = field(default=0)
    _ip_address: str = field(default="")
    _backplane_slot: Union[int, None] = field(default=None)
    _chassis_size: Union[int, None] = field(default=None)
    _port_child_counts: Dict[int, int] = field(default_factory=dict)
    # Pre-rendered <Ports> XML decoded from the module's RxDataCollection topology
    # blob (see ModuleBuilder._ports_from_data_collection). When set it replaces
    # the static PORT_STRUCTURES path; None falls back to that path.
    _ports_override: Union[str, None] = field(default=None)
    # Communications / ExtendedProperties / Description (optional)
    _description: str = field(default="")
    _comm_method: Union[str, None] = field(default=None)
    # Module identity class word (u16 @ ext-attr 0x001[0:2]); drives the
    # <Communications> emit gate. -1 when unknown (truncated/fallback module).
    _class_word: int = field(default=-1)
    # CIP product type (u16 @ ext-attr 0x001[4:6]) and the module's own modid
    # (u32 @ ext-attr 0x001[0x2C:]); used to zero an axis-less motion drive's
    # MotionSync RPI. 0 when unknown.
    _product_type: int = field(default=0)
    _modid: int = field(default=0)
    # Each entry: (name, rpi_str, conn_type_str)
    # Each connection is a dict with keys: name, type, rpi, unicast, event_id,
    # stub_output (bool, drives the InputTag/OutputTag stubs), and the optional
    # InputCxnPoint/OutputCxnPoint/InputSize/OutputSize (present only when OEM
    # emits them, set by ModuleBuilder). Values are decoded from the connection
    # record when available, else carry the defaults the import accepts.
    _connections: List[dict] = field(default_factory=list)
    _extended_properties: str = field(default="")
    # True when the project's OPC UA server is enabled; module IO tag stubs then
    # carry OpcUaAccess="None" (see ExportL5x.project_flags).
    _opc_ua: bool = field(default=False)
    # ConfigTag content for this module: the rendered inner XML (binary + Decorated
    # <Data> blocks, captured byte-for-byte from the module's controller :C tag) and
    # the ConfigSize. Both None -> no <ConfigTag> is emitted. Set by ModuleBuilder
    # only for a module that owns a :C controller tag (the proven discriminator).
    _config_inner: Union[str, None] = field(default=None)
    _config_size: Union[int, None] = field(default=None)
    # Connection InputTag / OutputTag <Data> content, captured from the module's
    # controller :I / :O tags. InputTag carries the Decorated block only; OutputTag
    # carries the binary + Decorated blocks. None -> the empty stub is emitted.
    # Populated into a connection only when the module has a single connection of
    # that tag type (an unambiguous mapping; see to_xml).
    _input_inner: Union[str, None] = field(default=None)
    _output_inner: Union[str, None] = field(default=None)
    # The module's safety output (:SO) tag inner, used by a SafetyOutput*
    # connection's <OutputTag> (a standard Output connection uses _output_inner /
    # the :O tag). Kept verbatim like _output_inner.
    _safety_output_inner: Union[str, None] = field(default=None)
    # The module's status (:S) tag inner, used by a Status/MotionDiagnostics
    # connection's <InputTag> (the others use _input_inner / the :I tag).
    _status_inner: Union[str, None] = field(default=None)
    # Whether the module owns an :I / :O tag (a rack card's input :I tag carries no
    # design-value image, so _input_inner can be None even when the card has input);
    # used to decide a <RackConnection>'s InAliasTag / OutAliasTag presence.
    _rack_has_input: bool = field(default=False)
    _rack_has_output: bool = field(default=False)
    # True when the module owns a safety connection -> emit SafetyEnabled="true".
    _safety_enabled: bool = field(default=False)
    # <ConfigData>/<ConfigScript> for a module with a config image but no controller
    # :C tag (mutually exclusive with the ConfigTag above). Each is (hex_data, size)
    # or None. The raw <Data> is masked by the comparator; the size attribute is the
    # scored value. Emitted before <Connections> (ConfigData first, then ConfigScript).
    _config_data: "Union[Tuple[str, int], None]" = field(default=None)
    _config_script: "Union[Tuple[str, int], None]" = field(default=None)
    # Drive ADC (PowerFlex etc.), Safety Network Number, and per-module safety
    # signature; each None omits its attribute.
    _drives_adc_enabled: Union[str, None] = field(default=None)
    _drives_adc_mode: Union[str, None] = field(default=None)
    _safety_network: Union[str, None] = field(default=None)
    _safety_signature: Union[str, None] = field(default=None)
    _safety_signature_timestamp: Union[str, None] = field(default=None)
    # Drive-peripheral modules carry their own (pre-display) identity in the
    # UserDefined* attributes plus ShutdownParentOnFault. All None on ordinary
    # modules (the attributes are then omitted).
    _ud_vendor: Union[int, None] = field(default=None)
    _ud_product_type: Union[int, None] = field(default=None)
    _ud_product_code: Union[int, None] = field(default=None)
    _ud_major: Union[int, None] = field(default=None)
    _ud_minor: Union[int, None] = field(default=None)
    _ud_catalog_number: Union[str, None] = field(default=None)
    _shutdown_parent_on_fault: Union[str, None] = field(default=None)

    def __post_init__(self):
        super().__post_init__()
        self._export_name = "Module"

    def to_xml(self) -> str:
        # Hash-named drive peripherals have no Name attribute in Logix-exported L5X.
        name_attr = "" if self.name == "?" else f'Name="{self.name}" '
        # The reference writes SafetyEnabled="true" on a safety module (one that
        # owns a safety connection); it omits the attribute on non-safety modules.
        safety_attr = ' SafetyEnabled="true"' if self._safety_enabled else ''
        if self._safety_network is not None:
            safety_attr += f' SafetyNetwork="{self._safety_network}"'
        if self._safety_signature is not None:
            safety_attr += f' SafetySignature="{self._safety_signature}"'
        if self._safety_signature_timestamp is not None:
            safety_attr += f' SafetySignatureTimestamp="{html.escape(self._safety_signature_timestamp, quote=True)}"'
        if self._drives_adc_enabled is not None:
            safety_attr += (f' DrivesADCEnabled="{self._drives_adc_enabled}"'
                            f' DrivesADCMode="{self._drives_adc_mode}"')
        # Drive-peripheral modules carry the peripheral's own identity in
        # UserDefined* attributes (between Minor and ParentModule in the reference).
        ud_attr = ""
        if self._ud_vendor is not None:
            ud_attr = (
                f' UserDefinedVendor="{self._ud_vendor}"'
                f' UserDefinedProductType="{self._ud_product_type}"'
                f' UserDefinedProductCode="{self._ud_product_code}"'
                f' UserDefinedMajor="{self._ud_major}"'
                f' UserDefinedMinor="{self._ud_minor}"'
            )
        shutdown_attr = (f' ShutdownParentOnFault="{self._shutdown_parent_on_fault}"'
                         if self._shutdown_parent_on_fault is not None else "")
        # UserDefinedCatalogNumber is the last <Module> attribute in the reference.
        udcn_attr = (f' UserDefinedCatalogNumber="{html.escape(self._ud_catalog_number, quote=True)}"'
                     if self._ud_catalog_number else "")
        attrs = (
            f'{name_attr}'
            f'CatalogNumber="{self.catalog_number}" '
            f'Vendor="{self.vendor}" '
            f'ProductType="{self.product_type}" '
            f'ProductCode="{self.product_code}" '
            f'Major="{self.major}" '
            f'Minor="{self.minor}"{ud_attr} '
            f'ParentModule="{self.parent_module}" '
            f'ParentModPortId="{self.parent_mod_port_id}" '
            f'Inhibited="{self.inhibited}" '
            f'MajorFault="{self.major_fault}"{shutdown_attr}'
            f'{safety_attr}{udcn_attr}'
        )

        # Optional <Description>
        desc_xml = ""
        if self._description:
            desc_xml = f'<Description>\n<![CDATA[{self._description}]]>\n</Description>'

        ekey = f'<EKey State="{self._ekey_state}"/>'
        ports = self._build_ports_xml()

        # <Communications> section. A module emits one when its identity class word
        # is not a structural/bus class that never carries Communications, gated by
        # its content for the few mixed classes. Validated 0-false-positive pool-wide
        # (the class word distinguishes ports/buses/controllers, which omit it, from
        # devices, which emit it; CIP/ControlNet bridges with only a config image but
        # no I/O are the one mixed case that must NOT emit). When emitted, the
        # CommMethod attribute is present only when one was recovered.
        comm_xml = ""
        _has_config = (self._config_inner is not None
                       or self._config_data is not None
                       or self._config_script is not None)
        _nconn = len(self._connections)
        _cw = self._class_word
        if _cw in (0x106, 0x609, 0x60A, 0x900):
            _emit_comm = False
        elif _cw in (0x104, 0x109):
            _emit_comm = _nconn > 0 or self._comm_method is not None
        elif _cw == 0x800:
            _emit_comm = _nconn > 0 or _has_config or self._comm_method is not None
        else:
            _emit_comm = True
        if _emit_comm:
            # InputTag/OutputTag carry the module's I/O data image, sourced from its
            # controller :I / :O tags. The data is placed only when the module has a
            # single connection of that tag type, so the module->tag mapping is
            # unambiguous; a multi-connection module (each connection carrying its own
            # distinct image) keeps the empty stub. ExternalAccess is always
            # Read/Write; OpcUaAccess="None" is added when the project OPC UA server
            # is on (one rule for every IO tag).
            def _io_tag(tag: str, inner: Union[str, None]) -> str:
                opc = ' OpcUaAccess="None"' if self._opc_ua else ''
                if inner:
                    return f'<{tag} ExternalAccess="Read/Write"{opc}>{inner}</{tag}>'
                # The reference writes <Comments> on a module InputTag/OutputTag
                # only when there is at least one operand <Comment> (always beside
                # <Data>); it never emits a bare empty <Comments/>. With no data and
                # no per-operand comments, emit a self-closing stub.
                return f'<{tag} ExternalAccess="Read/Write"{opc}/>'

            conn_parts: List[str] = []
            for c in self._connections:
                safe_name = html.escape(c["name"], quote=True)
                # A motion sync/async/event connection carries no I/O assembly:
                # emit a bare <Connection> with no InputTag/OutputTag. Otherwise an
                # InputTag is present when the connection carries input data
                # (InputSize > 0) and an OutputTag when it carries output data. Each
                # reuses the module's backing tag content: the InputTag uses the :I
                # tag (or the status :S tag for a Status/MotionDiagnostics
                # connection), the OutputTag uses the :O tag. Connections that did
                # not decode keep the prior always-emit behaviour (has_input/
                # has_output/is_motion default True/False).
                tag_stubs = ""
                if not c.get("is_motion", False):
                    if c.get("has_input", True):
                        cn = c["name"]
                        inner = (self._status_inner
                                 if ("Status" in cn or "MotionDiagnostics" in cn)
                                 else self._input_inner)
                        tag_stubs += _io_tag("InputTag", inner)
                    if c.get("has_output", True):
                        # A safety output connection's <OutputTag> reuses the
                        # module's safety output (:SO) backing tag when the module
                        # owns one (motion-drive safety, e.g. CIP_Motion_Device_
                        # Safety2); a point-safety module instead carries its safety
                        # output image in the plain :O tag, so fall back to that
                        # (and a standard output always uses :O).
                        out_inner = self._output_inner
                        if ("Safety" in c.get("type", "")
                                and self._safety_output_inner is not None):
                            out_inner = self._safety_output_inner
                        tag_stubs += _io_tag("OutputTag", out_inner)
                # Connection point / size attributes, present only when OEM emits
                # them (a generic/drive Output connection, or a data-driven one).
                extra = "".join(
                    f' {a}="{c[a]}"'
                    for a in ("InputCxnPoint", "OutputCxnPoint", "OutputSize", "InputSize")
                    if a in c
                )
                # Safety timing attributes (SafetyInput/Output + Safety*DataDriven),
                # then the data-driven block (Priority, InputConnectionType,
                # InputProductionTrigger, ConnectionPath, tag suffixes) -- each
                # emitted only when decoded for this connection.
                modern = "".join(
                    f' {a}="{html.escape(str(c[a]), quote=True)}"'
                    for a in ("TimeoutMultiplier", "NetworkDelayMultiplier",
                              "ReactionTimeLimit", "MaxObservedNetworkDelay",
                              "Priority", "InputConnectionType", "InputProductionTrigger",
                              "ConnectionPath", "InputTagSuffix", "OutputTagSuffix",
                              "SafetySignature", "SafetySignatureTimestamp")
                    if a in c
                )
                # Unicast is rendered only on connection types that carry it
                # (safety always; plain Input/Output only when point-to-point).
                uni = f' Unicast="{c["unicast"]}"' if c.get("unicast_present", True) else ""
                conn_parts.append(
                    f'<Connection Name="{safe_name}" RPI="{c["rpi"]}" Type="{c["type"]}"'
                    f'{extra}'
                    f' EventID="{c["event_id"]}" ProgrammaticallySendEventTrigger="false"'
                    f'{modern}{uni}>'
                    f'{tag_stubs}'
                    f'</Connection>'
                )
            # A rack-optimized module (the rack CommMethod) bundles its slot into
            # the adapter's rack connection rather than owning a discrete
            # <Connection>, so it emits a single <RackConnection> carrying an
            # <InAliasTag>/<OutAliasTag> for each direction the card has data in.
            # The card's input/output data presence is its captured :I / :O tag
            # (input cards -> In; basic output cards -> Out; electronic output
            # cards, which also carry a diagnostic input image, -> both).
            if self._comm_method == _RACK_COMM_METHOD:
                aliases = ""
                if self._rack_has_input:
                    aliases += "<InAliasTag/>"
                if self._rack_has_output:
                    aliases += "<OutAliasTag/>"
                connections_xml = (
                    f"<Connections><RackConnection>{aliases}"
                    f"</RackConnection></Connections>"
                )
            else:
                joined = "".join(conn_parts)
                # A safety module's combined signature rides on the <Connections>
                # container (distinct from each connection's own SafetySignature).
                _csig = next((c.get("_connections_signature")
                              for c in self._connections
                              if c.get("_connections_signature")), None)
                _csig_attr = ""
                if _csig:
                    _csig_attr = f' SafetySignature="{html.escape(_csig, quote=True)}"'
                    _cts = next((c.get("_connections_signature_ts")
                                 for c in self._connections
                                 if c.get("_connections_signature")), None)
                    if _cts:
                        _csig_attr += (' SafetySignatureTimestamp="'
                                       f'{html.escape(str(_cts), quote=True)}"')
                if joined:
                    connections_xml = f'<Connections{_csig_attr}>{joined}</Connections>'
                else:
                    connections_xml = (f'<Connections{_csig_attr}/>' if _csig_attr
                                       else '<Connections/>')
            # <ConfigTag> — the module's config assembly image, emitted as the first
            # child of <Communications> (before <Connections>). The content is the
            # module's controller :C tag <Data> blocks (captured verbatim); a module
            # gets a ConfigTag iff it owns such a tag. ExternalAccess is always
            # Read/Write; OpcUaAccess="None" mirrors the IO-tag-stub rule.
            config_xml = ""
            if self._config_inner is not None and self._config_size is not None:
                opc = ' OpcUaAccess="None"' if self._opc_ua else ''
                config_xml = (
                    f'<ConfigTag ConfigSize="{self._config_size}"'
                    f' ExternalAccess="Read/Write"{opc}>'
                    f'{self._config_inner}</ConfigTag>'
                )
            elif self._config_data is not None:
                # <ConfigData> — the raw config image for a module with no :C tag
                # (mutually exclusive with <ConfigTag>). Single raw <Data> block; the
                # comparator masks the bytes, the ConfigSize is the scored value.
                cd_hex, cd_size = self._config_data
                config_xml = (
                    f'<ConfigData ConfigSize="{cd_size}">'
                    f'<Data>{cd_hex}</Data></ConfigData>'
                )
            # <ConfigScript> — an optional raw script blob, after ConfigData/ConfigTag
            # and before <Connections>. Size is the blob byte length (scored); the
            # <Data> bytes are masked.
            script_xml = ""
            if self._config_script is not None:
                cs_hex, cs_size = self._config_script
                # A safety module renders the script blob as <SafetyScript>; a
                # standard module as <ConfigScript> (same image + Size, different tag).
                _stag = "SafetyScript" if self._safety_enabled else "ConfigScript"
                script_xml = (
                    f'<{_stag} Size="{cs_size}">'
                    f'<Data>{cs_hex}</Data></{_stag}>'
                )
            # PrimCxn*/SecCxn* connection-size attributes on <Communications>.
            # A generic-profile module (Rockwell vendor, ProductType 0), a DeviceNet
            # scanner (ProductType 12), or a 753-NET drive (ProductType 123) records
            # its primary "Standard" Output connection's assembly sizes at the
            # Communications level — the assembly is user-configured rather than fixed
            # by a catalog Module Definition. Catalog cards, comms bridges/adapters,
            # drive-peripheral modules and specific drive profiles omit them, so the
            # primary connection must be present and decoded (Name "Standard",
            # Type "Output"). The values are that connection's decoded Input/Output
            # sizes; a two-connection scanner also states its secondary "Status"
            # Input connection's input size (SecCxnInputSize only).
            primcxn_attrs = ""
            if self.vendor == 1 and self.product_type in (0, 12, 123):
                prim = next(
                    (c for c in self._connections
                     if c.get("name") == "Standard" and c.get("type") == "Output"
                     and "in_size" in c),
                    None,
                )
                if prim is not None:
                    primcxn_attrs = (
                        f' PrimCxnInputSize="{prim["in_size"]}"'
                        f' PrimCxnOutputSize="{prim["out_size"]}"'
                    )
                    sec = next(
                        (c for c in self._connections
                         if c.get("name") == "Status" and c.get("type") == "Input"
                         and "in_size" in c),
                        None,
                    )
                    if sec is not None:
                        primcxn_attrs += f' SecCxnInputSize="{sec["in_size"]}"'
            cm_attr = (f' CommMethod="{self._comm_method}"'
                       if self._comm_method is not None else '')
            comm_xml = (
                f'<Communications{cm_attr}{primcxn_attrs}>'
                f'{config_xml}{script_xml}{connections_xml}'
                f'</Communications>'
            )

        # <ExtendedProperties> section — only emitted when public data is known.
        ext_xml = ""
        if self._extended_properties:
            ext_xml = f'<ExtendedProperties><public>{self._extended_properties}</public></ExtendedProperties>'

        return f'<Module {attrs}>{desc_xml}{ekey}{ports}{comm_xml}{ext_xml}</Module>'

    def _build_ports_xml(self) -> str:
        """Build the <Ports>...</Ports> XML section for this module.

        Looks up the port structure from PORT_STRUCTURES by (vendor, product_type,
        product_code). Falls back to <Ports/> if the catalog number is not in the table.
        """
        # Prefer the real per-module topology decoded from RxDataCollection when
        # available; the static catalog covers only CPUs/EN bridges.
        if self._ports_override is not None:
            return self._ports_override
        key = (self.vendor, self.product_type, self.product_code)
        port_defs = PORT_STRUCTURES.get(key)
        if port_defs is None:
            return '<Ports/>'

        is_root = self._is_root
        port_parts: List[str] = []

        for pd in port_defs:
            # --- Upstream direction ---
            # Root modules (self-parenting CPU) have all ports downstream.
            # For other modules: if upstream_fixed=True, use the static upstream_port value.
            # If upstream_fixed=False, determine from parent_mod_port_id (the port on the
            # parent module that this module connects through — when that matches port_id,
            # this port faces upstream).
            if is_root:
                upstream_str = "false"
            elif pd.upstream_fixed:
                upstream_str = "true" if pd.upstream_port else "false"
            else:
                upstream_str = "true" if pd.port_id == self.parent_mod_port_id else "false"

            # --- Address attribute ---
            if pd.address_mode == "omit":
                addr_attr = ""
            elif pd.address_mode == "slot":
                # Non-upstream ICP ports (remote chassis owner): use _backplane_slot if known.
                if upstream_str == "false" and self._backplane_slot is not None:
                    addr_attr = f' Address="{self._backplane_slot}"'
                else:
                    addr_attr = f' Address="{self._slot if self._slot != 0xFFFFFFFF else 0}"'
            elif pd.address_mode == "zero":
                addr_attr = ' Address="0"'
            else:  # "empty" — use IP from binary if present, else omit value
                addr_attr = f' Address="{self._ip_address}"'

            # --- Bus element ---
            # Bus is only emitted on downstream (Upstream="false") ports.
            # upstream ports never carry a Bus element.
            is_upstream = (upstream_str == "true")
            bus_xml = self._bus_xml(pd, is_upstream)

            if bus_xml:
                port_parts.append(
                    f'<Port Id="{pd.port_id}"{addr_attr} Type="{pd.port_type}" Upstream="{upstream_str}">\n'
                    f'{bus_xml}\n'
                    f'</Port>\n'
                )
            else:
                port_parts.append(
                    f'<Port Id="{pd.port_id}"{addr_attr} Type="{pd.port_type}" Upstream="{upstream_str}"/>\n'
                )

        return f'<Ports>\n{"".join(port_parts)}</Ports>\n'

    def _bus_xml(self, pd, is_upstream: bool) -> str:
        """Return the Bus XML string for a port, or '' if no Bus element should be emitted.

        Bus elements are only present on downstream (Upstream=false) ports.
        """
        if is_upstream:
            return ""
        mode = pd.bus_mode
        if mode == "none":
            return ""
        if mode == "always":
            return "<Bus/>"
        if mode == "chassis":
            # Bus size comes only from the binary (RxDataCollection topology /
            # Output-connection record). No static per-catalog size: when the
            # ACD does not carry one, emit a size-less <Bus/>.
            if self._chassis_size is not None:
                return f'<Bus Size="{self._chassis_size}"/>'
            return "<Bus/>"
        if mode == "children_or_none":
            child_count = self._port_child_counts.get(pd.port_id, 0)
            if self._chassis_size is not None:
                child_count = max(child_count, self._chassis_size)
            if child_count == 0:
                return ""
            return f'<Bus Size="{child_count}"/>'
        # "children" mode: child count, but never less than _chassis_size when known
        # (handles remote chassis with empty slots not represented as child modules).
        child_count = self._port_child_counts.get(pd.port_id, 0)
        if self._chassis_size is not None:
            child_count = max(child_count, self._chassis_size)
        return f'<Bus Size="{child_count}"/>'


def _module_identity_e1(cur, object_id: int, raw_rec: bytes,
                        short_header: bool) -> "Tuple[bytes, Union[int, None], str]":
    """Resolve a module record's identity blob via the shared recovery chain.

    One implementation of the three copies that had drifted apart
    (ModuleBuilder.build, the _pass_modules modid map, the :C-owner map):

    1. Parse the truncated comps ``record`` buffer (RxGeneric; the record must
       be a cip-0x69 module) and take ext-attr 0x001. On long-header (V24+)
       projects re-saved by a newer Studio, count_record reads garbage and the
       tail is trimmed, so the parse can throw -- that routes to tier 3.
    2. When the parsed record does not surface a >= 0x30 attr 0x001 (V10..V20
       projects), alias the identity stored inline behind the 44 02 00 00
       marker (the u32 length 0x244 of the identity TLV); the bytes after the
       length prefix are byte-identical to the 0x001 attribute. The marker is
       only trusted on a record that parsed as a cip-0x69 module -- a garbage
       buffer that happens to contain the marker must not mask tier 3.
    3. When both miss (including a buffer that does not parse at all), recover
       from the size-eos comps record body: cip-checked at body offset 10,
       attrs read with read_value_attrs(full=True, body_mode=True) (memoized
       by CompsRecord.record_attrs), adopted only when >= 0x30.

    Returns ``(e1, comment_id, source)``:
      e1         -- identity bytes; may still be shorter than 0x30 (callers gate)
      comment_id -- from the parsed prelude, else from the comps body offset 12
                    (only when the body yielded a usable blob); None when the
                    record is not provably a cip-0x69 module
      source     -- "record" | "marker" | "full"; callers with per-source map
                    policies dispatch on it
    """
    e1 = b""
    comment_id = None
    source = "record"
    parsed = False
    try:
        r = RxGeneric.from_bytes(raw_rec)
        if r.cip_type == 0x69:
            # The ext-attr tail parses lazily; materialise it here so a
            # garbage count_record still routes to the comps_full recovery.
            e1 = {er.attribute_id: bytes(er.value)
                  for er in r.extended_records}.get(0x001, b"")
            comment_id = r.comment_id
            parsed = True
    except Exception:
        parsed = False
    if parsed and len(e1) < 0x30:
        mk = raw_rec.find(b"\x44\x02\x00\x00")
        if mk >= 0 and len(raw_rec) - (mk + 4) >= 0x30:
            e1 = raw_rec[mk + 4:]
            source = "marker"
    if len(e1) < 0x30:
        try:
            row = cur.execute(
                "SELECT record FROM comps WHERE object_id=?", (object_id,)
            ).fetchone()
            body = bytes(row[0]) if row and row[0] is not None else None
            if (body and len(body) >= 14
                    and struct.unpack_from("<H", body, 10)[0] == 0x69):
                fe1 = CompsRecord.record_attrs(
                    cur, object_id, short_header).get(0x001, b"")
                if len(fe1) >= 0x30:
                    e1 = fe1
                    source = "full"
                    if comment_id is None:
                        comment_id = struct.unpack_from("<H", body, 12)[0]
        except Exception:
            pass
    return e1, comment_id, source


def _build_rxdata_holders(cur, short_header: bool = False
                          ) -> "Dict[int, List[Tuple[int, bytes]]]":
    """Ordered RxDataCollection child index, keyed by comment-id link.

    Every module points at its backing hash-named RxDataCollection child by
    comment_id (module e1[0x24] & 0xFFFF == child record[12:14]); the ports /
    CommMethod / ExtendedProperties / UserDefinedCatalogNumber decoders all
    resolve that link by scanning every collection's children in order. This
    builds that scan's result once per controller: {cid: [(child_oid, raw)]},
    children kept in collection-then-row order. Deliberately ORDER-PRESERVING
    and not unique-only (unlike connections._build_config_holders): a decoder
    walks ALL same-cid children until one yields its payload, so dropping
    ambiguous keys would forfeit recoveries. Children too short to carry the
    link (< 14 bytes) can never match and are skipped.

    On a LONG-header project each child's ``raw`` is bounded to its DECLARED
    record length (the u32 at the full-payload offset 0, minus the 148-byte
    long header), so the raw-tail scans above (<public>/<UDCN>/<CF>, which read
    to the buffer end) see only the primary record and never the appended
    sub-blobs a size-eos comps buffer would expose. This is a no-op on the
    still-truncated buffer (bound == len) and reconstructs it exactly once the
    buffer is un-truncated; short-header records are already size-eos and carry
    no separate truncation, so they are left as-is.
    """
    holders: Dict[int, List[Tuple[int, bytes]]] = {}
    dead = CompsRecord.dead_oids(cur, short_header)
    cur.execute("SELECT object_id FROM comps WHERE comp_name='RxDataCollection'")
    coll_oids = [r[0] for r in cur.fetchall()]
    for coll_oid in coll_oids:
        cur.execute(
            "SELECT c.object_id, c.record, substr(cf.record, 1, 4) "
            "FROM comps c LEFT JOIN comps_full cf ON c.object_id = cf.object_id "
            "WHERE c.parent_id=?", (coll_oid,))
        for child_oid, raw, len_bytes in cur.fetchall():
            # A dead-relic (FDFD-only) child never backs a live module; skipping
            # it keeps this cid index flip-invariant (its realigned body would
            # otherwise change the cid it contributes). Long-header only.
            if child_oid in dead:
                continue
            raw = bytes(raw) if raw else b""
            if len(raw) < 14:
                continue
            if not short_header and len_bytes is not None and len(len_bytes) == 4:
                body_len = int.from_bytes(bytes(len_bytes), "little") - 148
                if 0 < body_len < len(raw):
                    raw = raw[:body_len]
            cid = int.from_bytes(raw[12:14], "little")
            holders.setdefault(cid, []).append((child_oid, raw))
    return holders


@dataclass
class ModuleBuilder(L5xElementBuilder):
    # Map from modid (u32) → module name, built by ControllerBuilder and passed in.
    _modid_to_name: Dict[int, str] = field(default_factory=dict)
    # Ordered RxDataCollection child index {cid: [(child_oid, raw)]}, built once
    # per controller by _build_rxdata_holders and shared by every module; the
    # comment_id-link decoders (ports / CommMethod / ExtendedProperties / UDCN)
    # walk their cid's list in the original collection scan order. The decrypted
    # ext-attr dicts those decoders fall back to are memoized per cursor by
    # CompsRecord.full_attrs.
    _rxdata_by_cid: "Dict[int, List[Tuple[int, bytes]]]" = field(default_factory=dict)
    # Map connection record object_id → decoded {RPI, Unicast, EventID}, built once
    # by ControllerBuilder (see _build_connection_map). Empty -> connection values
    # fall back to the import defaults.
    _conn_decode: Dict[int, dict] = field(default_factory=dict)
    # Module <Communications> tag content, built by ControllerBuilder from the
    # module's controller config (:C), input (:I) and output (:O) tags. Keyed by the
    # &hex object-id reference: (parent_object_id, slot) for a slotted card and
    # (self_object_id, None) for an Ethernet device. Each value is a dict with
    # optional keys "C" -> (config_inner_xml, config_size), "I" -> input_decorated_xml,
    # "O" -> output_inner_xml. Empty -> no ConfigTag/populated IO tags.
    _io_map: Dict[tuple, dict] = field(default_factory=dict)
    # Map module modid (u32) → comps object_id, built with the short-header marker
    # fallback so it is complete on V10..V20 too. Lets a module resolve its parent's
    # object_id for the _io_map key without depending on friendly-name resolution
    # (which can mis-parent motion axes on short-header projects).
    _modid_to_oid: Dict[int, int] = field(default_factory=dict)
    # RxDataCollection holder indexes for <ConfigData>/<ConfigScript> (modules with a
    # config image but no controller :C tag). Built by _build_config_holders.
    _cfg_by_mr28: Dict[int, int] = field(default_factory=dict)
    _cfg_by_cid: Dict[int, int] = field(default_factory=dict)
    _cfg_pool: set = field(default_factory=set)
    _short_header: bool = field(default=False)

    def _ip_from_data_collection(self, icp_slot: int) -> str:
        """Look up the Ethernet IP for a local backplane module via RxDataCollection.

        Local bridge modules (e.g. EN2T in the main chassis) store their IP as XML
        in hash-named children of RxDataCollection. The record for a given module
        contains its ICP slot as Type="ICP" Addr="{slot}", which uniquely identifies it.
        """
        import re as _re
        needle = f'Type="ICP" Addr="{icp_slot}"'.encode()
        # Find RxDataCollection — it is a direct child of the controller object.
        self._cur.execute(
            "SELECT object_id FROM comps WHERE comp_name='RxDataCollection' LIMIT 1"
        )
        row = self._cur.fetchone()
        if not row:
            return ""
        coll_oid = row[0]
        # Fetch all children in batches and filter in Python (SQLite LIKE on BLOBs is unreliable).
        self._cur.execute(
            "SELECT record FROM comps WHERE parent_id=?", (coll_oid,)
        )
        for (raw,) in self._cur.fetchall():
            raw = bytes(raw)
            if needle not in raw:
                continue
            m = _re.search(rb'Type="EN" Addr="([^"]+)"', raw)
            return m.group(1).decode("ascii", errors="replace") if m else ""
        return ""

    def _extended_properties_from_data_collection(self, data_link: int) -> str:
        """Extract the <ExtendedProperties> <public> content for a module.

        The module's <public> block lives in the SAME hash-named RxDataCollection
        child that carries its port topology (see _ports_from_data_collection),
        linked by the module's comment_id at e1[0x24] (u32). That child is looked
        up by rec[12:14] == data_link & 0xFFFF in the shared _rxdata_by_cid index --
        the exact 1:1 key the ports decode uses. This resolves the correct record
        for every module type (backplane cards, EN bridges, PointIO adapters, drive
        peripherals); a module whose link finds no <public> yields "".

        Returns the inner content of <public>...</public>, or "" if absent. The
        record XML is often stored without the closing </public> tag (truncated in
        the ACD binary), so we reconstruct everything after <public>.
        """
        if not data_link:
            return ""
        import re as _re
        for child_oid, raw in self._rxdata_by_cid.get(data_link & 0xFFFF, []):
            xml_start = raw.find(b'<')
            xml_text = (raw[xml_start:].decode("latin-1", errors="replace")
                        if xml_start >= 0 else "")
            pub_start = xml_text.find("<public>")
            if pub_start < 0:
                # Source-protected modules store the <public> block only in the
                # DECRYPTED ext-attr 0x66 image (the raw record body is ciphertext,
                # so the plaintext scan above finds nothing). Same decrypt path the
                # UserDefinedCatalogNumber recovery uses for these records.
                img = CompsRecord.record_attrs(
                    self._cur, child_oid, self._short_header).get(0x66, b"")
                ds = img.find(b'<public>')
                if ds >= 0:
                    after = img[ds + len(b'<public>'):]
                    mm = _re.search(rb'</pub', after)
                    return (after[:mm.start()] if mm
                            else after.rstrip(b'\x00 \r\n')).decode(
                                "latin-1", errors="replace")
                continue
            after_pub = xml_text[pub_start + len("<public>"):]
            end_tag_m = _re.search(r'</pub', after_pub)
            if end_tag_m:
                return after_pub[:end_tag_m.start()]
            return after_pub.rstrip("\x00 \r\n")
        return ""

    def _udcn_from_data_collection(self, data_link: int) -> Union[str, None]:
        """UserDefinedCatalogNumber (device-profile name) for a drive-peripheral
        module. The profile record is the RxDataCollection child linked by the same
        comment_id the ports/ExtendedProperties use (rec[12:14] == data_link & 0xFFFF,
        via the shared _rxdata_by_cid index); its <UDCN>...</UDCN> tag is in the raw
        record bytes on short-header projects and in the decrypted ext-attr 0x66
        image on long-header ones. None when the linked record carries no <UDCN>
        (the drive itself, not a peripheral)."""
        if not data_link:
            return None
        for oid, raw in self._rxdata_by_cid.get(data_link & 0xFFFF, []):
            m = re.search(rb"<UDCN>([^<]*)</UDCN>", raw)
            if not m:
                img = CompsRecord.record_attrs(
                    self._cur, oid, self._short_header).get(0x66, b"")
                m = re.search(rb"<UDCN>([^<]*)</UDCN>", img)
            if m:
                return m.group(1).decode("ascii", errors="replace") or None
        return None

    def _comm_method_from_data_link(self, data_link: int) -> "Union[str, None]":
        """Resolve CommMethod (<CF>) from the module's comment_id link.

        STAGING: same record/key as _extended_properties_from_data_collection.
        Validated byte-exact pool-wide (990 GOOD / 0 WRONG). Emits nothing on a
        link-miss.
        """
        if not data_link:
            return None
        import re as _re
        for child_oid, raw in self._rxdata_by_cid.get(data_link & 0xFFFF, []):
            xml_start = raw.find(b'<')
            if xml_start >= 0:
                xml_text = raw[xml_start:].decode("latin-1", errors="replace")
                cf_m = _re.search(r'<CF>(\d+)</CF>', xml_text)
                if cf_m:
                    return cf_m.group(1)
            # Source-protected child: the <CF> is in the decrypted ext-attr image
            # (0x66, else 0x65/0x64), not the plaintext body.
            attrs = CompsRecord.record_attrs(
                self._cur, child_oid, self._short_header)
            for _aid in (0x66, 0x65, 0x64):
                img = attrs.get(_aid)
                if not img:
                    continue
                cf_m = _re.search(
                    rb'<CF>(\d+)</CF>', bytes(img))
                if cf_m:
                    return cf_m.group(1).decode()
        return None

    def _ports_from_data_collection(self, data_link: int,
                                    validate_controller: bool = False) -> "Union[str, None]":
        """Build the <Ports> block from the module's RxDataCollection topology blob.

        Every module stores, at e1[0x24] (u32), the comment_id of its backing
        RxDataCollection child; that child's record carries a plaintext
        ``<in><Port .../>...</in>`` blob with the real port topology (which the
        static PORT_STRUCTURES catalog does not cover). comment_id is unique among
        the blob-bearing children, so this is an exact 1:1 link -- it works for
        every module type (Ethernet drives, drive peripherals, PointIO adapters,
        backplane bridges), unlike an IP/slot heuristic which mislinks name-less
        peripherals that share a bus address across different parents.

        ``data_link`` is e1[0x24]. Modules whose link resolves to a child with no
        ``<in>`` blob (the controller and local-chassis cards, whose single ICP
        port is implied by slot and not stored) fall back to the static catalog.
        Returns the rendered ``<Ports>...</Ports>`` string, or None to fall back.
        """
        if not data_link:
            return None
        # Per-port Safety Network Numbers (safety modules only); injected into the
        # decoded ports. {} for non-safety modules.
        port_sn = self._port_safety_networks()

        def _finish(res):
            # A controller-chassis module's data_link can mis-resolve to an unrelated
            # I/O-adapter blob (seen on a corrupt project whose Local/Local2 link to a
            # FLEX adapter record). A real controller's own backplane port is one of
            # the known controller types; if none is present, the blob is not the
            # controller's -- fall back to the static catalog instead of emitting
            # FLEX ports for a CompactLogix. (Fail-safe: too-strict only forfeits a
            # recovery, never regresses.)
            # Prefix match: "Compact" covers Compact / CompactLogixL3xController /
            # CompactVirtualAdapter (CPUs name their own backplane port with the full
            # catalog), while FLEX-adapter types (Flex/FlexAC/FlexVA) match nothing
            # and are rejected.
            if res and validate_controller and not any(
                    f'Type="{t}' in res
                    for t in ("ICP", "Compact", "5069", "1768Ctrl3Slot", "PointIO")):
                return None
            return res

        # Blob children linked by comment_id (u16 @ rec[12]), via the shared
        # per-controller _rxdata_by_cid index.
        for child_oid, raw in self._rxdata_by_cid.get(data_link & 0xFFFF, []):
            # Prefer a complete plaintext blob.
            i = raw.find(b"<in")
            if i >= 0:
                j = raw.find(b"</in>", i)
                if j >= 0:
                    return _finish(self._decode_ports_blob(
                        raw[i:j + 5].decode("latin-1", errors="replace"), port_sn))
            # Otherwise the topology is in the child's decrypted ext-attr 0x66
            # image -- either the plaintext body was truncated mid-blob (the root
            # case) or the whole blob is encrypted there with no plaintext copy
            # (local-chassis I/O cards and many CompactLogix CPUs). Same SP-aware
            # fallback the sibling _*_from_data_collection methods use.
            try:
                img = CompsRecord.record_attrs(
                    self._cur, child_oid, self._short_header).get(0x66)
                if img:
                    txt = img.decode("latin-1", errors="replace")
                    ii = txt.find("<in")
                    jj = txt.find("</in>", ii) if ii >= 0 else -1
                    if ii >= 0 and jj >= 0:
                        return _finish(self._decode_ports_blob(
                            txt[ii:jj + 5], port_sn))
            except Exception:
                pass
            # neither plaintext nor 0x66 had a blob; try the next matching child
        return None

    def _port_safety_networks(self) -> dict:
        """Per-port Safety Network Numbers for a safety module's ports.

        A safety module's full identity ext-attr 0x001 carries a port -> SNN table:
            [u16 count][count x ([u16 port_id][6-byte little-endian network id])]
        The leading count (2..7), the ascending in-range (1..7) port ids, and a
        non-zero most-significant byte on every 48-bit network id make the table
        self-validating: a real CIP Safety Network Number is large (time/MAC seeded,
        MSB always set), so look-alike runs of small structured ints (seen on
        TimeSynchronize/ExtendedDevice records) are rejected. Each port's id is
        independent -- they need not share a base. Validated 0-FP/0-FN pool-wide
        (TP=51): present on safety controllers (e.g. 5069-L330ERMS2), absent on
        non-safety modules. Returns {port_id: "16#0000_xxxx_xxxx_xxxx"} or {}.
        """
        try:
            e0 = CompsRecord.record_attrs(
                self._cur, self._object_id, self._short_header).get(0x001, b"")
        except Exception:
            return {}
        n = len(e0)
        for off in range(2, n - 8):
            cnt = struct.unpack_from("<H", e0, off - 2)[0]
            if cnt < 2 or cnt > 7:
                continue
            ids, vals, p, ok = [], [], off, True
            for _ in range(cnt):
                if p + 8 > n:
                    ok = False
                    break
                pid = struct.unpack_from("<H", e0, p)[0]
                v = e0[p + 2:p + 8]
                # v[5] is the MSB of the 48-bit network id; a real CIP SNN always
                # has it set, which screens out small structured look-alike runs.
                if pid < 1 or pid > 7 or v[5] == 0:
                    ok = False
                    break
                if ids and pid <= ids[-1]:
                    ok = False
                    break
                ids.append(pid)
                vals.append(v)
                p += 8
            if not ok or len(ids) != cnt:
                continue
            out = {}
            for pid, v in zip(ids, vals):
                h = v[::-1].hex()
                out[pid] = f"16#0000_{h[0:4]}_{h[4:8]}_{h[8:12]}"
            return out
        return {}

    @staticmethod
    def _decode_ports_blob(blob: str, port_sn: dict = None) -> "Union[str, None]":
        """Render an ``<in>`` topology blob into an L5X ``<Ports>`` block.

        Rules (validated byte-for-byte against the reference): Type EN->Ethernet,
        others verbatim (ICP/DSI/SERCOS/5069); Upstream is false only when the
        blob port carries ``Ups="False"`` (absent => upstream true); Address is the
        ``Addr`` attribute (omitted when absent, e.g. a SERCOS motion port); a
        port followed by ``<Bus Size="N"/>`` emits ``<Bus Size="N"/>`` (the Max
        attribute is dropped); a Bus without a Size, and a downstream Ethernet
        bridge port with no Bus, emit an empty ``<Bus/>``; the ``<CF>`` element is
        dropped. Returns None when the blob has no ports.
        """
        import re as _re
        # Port Type is stored as a short code the reference expands to a full name.
        # Only codes the reference NEVER emits verbatim are expanded here (verified
        # pool-wide: 0 reference ports carry any of these short codes, and each maps
        # to exactly one full name). Codes the reference DOES keep verbatim -- e.g.
        # "PointIO" and "RhinoBP", which are correct on hundreds of ports and only
        # context-dependently expand elsewhere -- are deliberately NOT mapped so the
        # already-correct ports are untouched.
        type_map = {
            "EN": "Ethernet",
            "Cpt32EN": "CompactLogixL32Ethernet",
            "Cpt35EN": "CompactLogixL35Ethernet",
            "Cpt32E": "CompactLogixL32EController",
            "Cpt35E": "CompactLogixL35Controller",
            "CptVA": "CompactVirtualAdapter",
            "DN": "DeviceNet",
            "CN": "ControlNet",
        }
        port_sn = port_sn or {}
        ports = []
        for m in _re.finditer(r'<Port\b([^>]*?)(/?)>', blob):
            a = dict(_re.findall(r'(\w+)=["\']([^"\']*)["\']', m.group(1)))
            pid = a.get("Id")
            # A real port always has an Id. Blobs without one (seen on some V10/V11
            # controller/CPU records) use a structure this decoder does not model;
            # bail out so the caller falls back to the static catalog rather than
            # emit an Id="None" port the reference never has.
            if pid is None:
                return None
            ptype = type_map.get(a.get("Type"), a.get("Type"))
            addr = a.get("Addr")
            upstream = "false" if a.get("Ups") == "False" else "true"
            bus = None
            if m.group(2) != "/":
                rest = blob[m.end():]
                nxt = _re.search(r'<Port\b|</in>', rest)
                seg = rest[:nxt.start()] if nxt else rest
                bm = _re.search(r'<Bus\b([^>]*)>', seg)
                if bm:
                    ba = dict(_re.findall(r'(\w+)=["\']([^"\']*)["\']', bm.group(1)))
                    bus = ba.get("Size") if ba.get("Size") is not None else ""
            if bus is None and upstream == "false" and ptype == "Ethernet":
                bus = ""
            # A CompactLogix embedded-CPU backplane port (the full-catalog type names
            # CompactLogixL3xController / ...EController) and a 1768 controller's
            # 1768Ctrl3Slot backplane port both carry an empty <Bus/> in OEM that the
            # blob leaves implied (port self-closed). Validated pool-wide: every
            # CompactLogix*-typed (83) and every 1768Ctrl3Slot (5) Upstream=false port
            # has an empty Bus, 0 counterexamples.
            if (bus is None and upstream == "false"
                    and (ptype.startswith("CompactLogix") or ptype == "1768Ctrl3Slot")):
                bus = ""
            try:
                _pidi = int(pid)
            except (TypeError, ValueError):
                _pidi = 0
            addr_attr = f' Address="{addr}"' if addr is not None else ""
            # SafetyNetwork (safety modules only) follows Upstream, matching OEM.
            _snv = port_sn.get(_pidi)
            sn_attr = f' SafetyNetwork="{_snv}"' if _snv else ""
            head = (f'<Port Id="{pid}"{addr_attr} Type="{ptype}" '
                    f'Upstream="{upstream}"{sn_attr}')
            if bus is None:
                ports.append((_pidi, f"{head}/>\n"))
            elif bus == "":
                ports.append((_pidi, f"{head}>\n<Bus/>\n</Port>\n"))
            else:
                ports.append((_pidi, f'{head}>\n<Bus Size="{bus}"/>\n</Port>\n'))
        if not ports:
            return None
        # OEM emits ports in ascending Id order; some blobs store them out of order.
        ports.sort(key=lambda p: p[0])
        return f'<Ports>\n{"".join(s for _, s in ports)}</Ports>\n'

    def _chassis_size_from_data_collection(self) -> "Union[int, None]":
        """Read the local backplane Bus Size from the RxDataCollection record for the CPU.

        The root controller (Local) module stores its backplane configuration as XML in a
        hash-named child of RxDataCollection.  The record contains:
          <Port Id="1" Type="ICP" Addr="0" Ups="False"><Bus Max="17" Size="7"/></Port>
        We extract the Size attribute from the Bus element on the ICP port at Addr="0".
        """
        import re as _re
        self._cur.execute(
            "SELECT object_id FROM comps WHERE comp_name='RxDataCollection' LIMIT 1"
        )
        row = self._cur.fetchone()
        if not row:
            return None
        coll_oid = row[0]
        self._cur.execute(
            "SELECT record FROM comps WHERE parent_id=?", (coll_oid,)
        )
        needle = b'Type="ICP" Addr="0"'
        for (raw,) in self._cur.fetchall():
            raw = bytes(raw)
            if needle not in raw:
                continue
            text_start = raw.find(b"<")
            if text_start < 0:
                continue
            text = raw[text_start:].decode("latin-1", errors="replace")
            m = _re.search(r'<Bus\b[^>]*\bSize="(\d+)"', text)
            if m:
                return int(m.group(1))
        return None

    def build(self) -> Module:
        self._cur.execute(
            "SELECT comp_name, object_id, record FROM comps WHERE object_id=" + str(self._object_id)
        )
        row = self._cur.fetchone()
        db_name = row[0]
        raw_rec = bytes(row[2])

        # Hex-encoded names like $02cc5e9d$ are unnamed peripheral modules (drive expansion
        # cards, etc.).  Logix Designer exports these with Name="?".
        name = "?" if (db_name.startswith("$") and db_name.endswith("$")) else db_name

        # Identity recovery chain (truncated-record parse -> inline 44 02 00 00
        # marker alias -> untruncated comps_full), shared with the controller
        # module passes -- see _module_identity_e1 for the tier semantics.
        e1, comment_id, _src = _module_identity_e1(
            self._cur, self._object_id, raw_rec, self._short_header)
        if comment_id is None:
            # Not provably a cip-0x69 module (neither the record buffer nor
            # comps_full yields one): the all-zero fallback Module.
            return Module(name, name, "", 0, 0, 0, 0, 0, "Local", 1, "false",
                          "false")
        if len(e1) < 0x30:
            major_fault = "true" if name == "Local" else "false"
            return Module(name, name, "", 0, 0, 0, 0, 0, "Local", 1, "false", major_fault,
                          _is_root=(name == "Local"))

        # Fixed-offset identity fields, decoded by the ModuleIdentity grammar
        # (resources/templates/Comps/ModuleIdentity.ksy). The >= 0x30 gate above
        # guarantees every field through modid (@0x2C) is present (non-None).
        mi = ModuleIdentity.from_bytes(e1)
        class_word    = mi.class_word
        vendor        = mi.vendor
        product_type  = mi.product_type
        product_code  = mi.product_code
        # bit 7 of the major byte is a flag; strip it to get the firmware revision.
        major         = mi.major_raw & 0x7F
        minor         = mi.minor
        parent_modid  = mi.parent_modid
        parent_port   = mi.parent_port
        slot          = mi.slot

        # Genuine drive-peripheral expansion cards are hash-named ("?") AND carry a
        # PowerFlex drive product_type. The RHINOBP families (142/143/123, PF753/755)
        # export as ProductType=0 ProductCode=28 (RHINOBP-DRIVE-PERIPHERAL-MODULE);
        # the DSI families (150/127/151, PF525 and its DSI-port variants) export as
        # ProductCode=29 (DSI-DRIVE-PERIPHERAL-MODULE). CATALOG_NUMBERS maps
        # (vendor,0,28)/(vendor,0,29) so the lookup below resolves. Validated against
        # the reference: every hash-named vendor=1 module with one of these six
        # product types is a peripheral (28 of them carry PT 123/151 and none of those
        # carry a drive ProductCode), and the count matches the reference peripheral
        # set exactly -- no false positives. Ordinary hash-named modules (unresolved
        # 1756/1769 I/O cards, PT 7/10) keep their genuine PT/PC and real catalog.
        ud_vendor = ud_product_type = ud_product_code = ud_major = ud_minor = None
        shutdown_parent_on_fault = None
        if name == "?" and vendor == 1 and product_type in (142, 143, 123, 150, 127, 151):
            # The reference re-labels these as a generic drive-peripheral catalog
            # and preserves the peripheral's own identity in the UserDefined*
            # attributes (verified equal to the pre-display identity record fields).
            # ShutdownParentOnFault is exported on every drive-peripheral module and
            # is false across the reference pool (135/135).
            ud_vendor = vendor
            ud_product_type = product_type
            ud_product_code = product_code
            ud_major = major
            ud_minor = minor
            shutdown_parent_on_fault = "false"
            product_code = 29 if product_type in (150, 127, 151) else 28
            product_type = 0
            # The reference exports these drive-peripheral modules with a fixed
            # Major/Minor of 1/1 (the peripheral's own firmware revision in the
            # identity record is not surfaced); verified pool-wide.
            major = 1
            minor = 1

        # Resolve parent module name from the modid→name map built by ControllerBuilder.
        parent_name = self._modid_to_name.get(parent_modid, "Local")

        # MajorFault (ConfiguredAsMajorFault): bit 0 of e1[0x14]. Set on the root
        # CPU and on any module the user configured so a connection fault halts the
        # controller -- NOT root-only. (The prior parent==self rule only ever
        # flagged the root; validated e1[0x14]&1 on V20/V28/V32/V33/V35 vs OEM,
        # 164/164.) Root detection for ProcessorType/MajorRev now uses
        # parent_module==name directly (see ControllerBuilder), so it no longer
        # piggy-backs on this attribute.
        major_fault = "true" if (mi.flags & 0x01) else "false"
        # Inhibited: bit 2 (0x04) of the same flag byte e1[0x14] that holds
        # ConfiguredAsMajorFault (bit 0). Set when the user inhibited the module.
        # Validated bool(e1[0x14] & 0x04) pool-wide vs OEM: 110 true / 1845 false,
        # 0 false-positives / 0 false-negatives (every other bit of e1[0x14]
        # mis-classifies >=110 modules).
        inhibited = "true" if (mi.flags & 0x04) else "false"
        # EKey state from the keying mask at e1[0x0a]: 0 = no keying (Disabled),
        # nonzero (0x1f = all identity fields keyed) = a keyed module. Both
        # ExactMatch and CompatibleModule carry the full 0x1f mask, so the mask
        # alone classifies Disabled vs keyed; we emit CompatibleModule for keyed
        # modules (ExactMatch -- almost exclusively the root CPU -- needs a further
        # discriminator and is left as a follow-on). Validated on V20/V36 vs OEM;
        # the prior e1[0]&0x04 rule mis-keyed Disabled modules as CompatibleModule.
        # No keying (mask 0) -> Disabled. Otherwise the keyed state is ExactMatch
        # when bit 7 of the major byte e1[0x08] is clear, else CompatibleModule -- the
        # same flag bit stripped to read the firmware major. Validated against the
        # reference over keyed modules: 117 ExactMatch / 1313 CompatibleModule, the
        # byte value splits the two sets with no overlap (0 false-positive/negative).
        if mi.ekey_mask == 0:
            ekey_state = "Disabled"
        elif not (mi.major_raw & 0x80):
            ekey_state = "ExactMatch"
        else:
            ekey_state = "CompatibleModule"

        # IP address: stored at e1[0x30] as a u16 length-prefixed ASCII string for modules
        # that connect via Ethernet upstream (parent_port == 2). Local backplane bridge
        # modules (parent_port == 1, e.g. local EN2T) leave e1[0x32] zero — their IP is
        # stored as XML in a child of RxDataCollection, keyed by ICP slot number.
        # mi.ip_raw is None when the blob ends before 0x33 or the length is 0;
        # a blob truncated mid-string yields the bytes that remain (the grammar
        # clamps), matching the old slice.
        own_ip = ""
        if mi.ip_raw is not None:
            own_ip = mi.ip_raw.rstrip(b"\x00").decode("ascii", errors="replace")
        ip_address = own_ip
        if not ip_address and slot:
            ip_address = self._ip_from_data_collection(slot)

        # For modules that own a remote backplane (e.g. remote chassis EN2T), the Output
        # connection record under RxMapConnectionCollection stores the chassis size at [0x4e]
        # and the module's own slot in that chassis at [0x6e].
        backplane_slot = None
        chassis_size = None
        self._cur.execute(
            "SELECT o.record FROM comps coll "
            "JOIN comps o ON o.parent_id = coll.object_id AND o.comp_name = 'Output' "
            "WHERE coll.parent_id = ? AND coll.comp_name = 'RxMapConnectionCollection'",
            (self._object_id,),
        )
        out_row = self._cur.fetchone()
        if out_row:
            out_rec = bytes(out_row[0])
            if len(out_rec) > 0x70:
                backplane_slot = struct.unpack("<H", out_rec[0x6e:0x70])[0]
                chassis_size   = struct.unpack("<H", out_rec[0x4e:0x50])[0]

        # For the root (Local) CPU module (slot=0xFFFFFFFF, self-parenting), the Output
        # connection record is absent.  The backplane chassis size is stored in the
        # RxDataCollection hash child that carries the Local module's ICP port at Addr="0".
        # Example: <Port Id="1" Type="ICP" Addr="0" Ups="False"><Bus Max="17" Size="7"/></Port>
        if chassis_size is None and slot == 0xFFFFFFFF:
            chassis_size = self._chassis_size_from_data_collection()

        # --- Description ---
        # Module descriptions are stored in the comments table keyed by
        # (comment_id * 0x10000 + cip_type), same as for tags. The module's own
        # description carries object_id == 1; rows sharing the key with a nonzero
        # object_id are scratch values (e.g. export timestamps) whose record_string
        # would otherwise leak in as a fabricated Description, so require object_id == 1.
        # The identity chain above guarantees a cip-0x69 module record, so the
        # comment key's cip component is the literal 0x69.
        description = ""
        if self._short_header:
            # sub_record_length filter (a module is 0x69) skips a cip-0x68 tag
            # that shares this comment_id.
            description = short_own_description(self._cur, comment_id, 0x69) or ""
        else:
            description = own_description(
                self._cur, (comment_id * 0x10000) + 0x69) or ""

        # --- Communications and ExtendedProperties ---
        # CommMethod is resolved from the module's ICP slot / IP address. The
        # <ExtendedProperties> <public> block comes from the hash-named
        # RxDataCollection child the module links to by comment_id (e1[0x24]); this
        # 1:1 link resolves the right record for every module type (backplane cards,
        # EN bridges, PointIO adapters, drive peripherals), where the slot/IP
        # heuristic mislinked or missed them.
        comm_method: Union[str, None] = None
        connections: List[dict] = []
        extended_properties = ""
        data_link = mi.data_link
        if not data_link:
            # The truncated comps `record` copy can zero the data_link (e1[0x24]),
            # notably for the root controller; the untruncated comps_full stream
            # carries it. Recover it before giving up on the port topology.
            try:
                _dl = ModuleIdentity.from_bytes(CompsRecord.record_attrs(
                    self._cur, self._object_id, self._short_header
                ).get(0x001, b"")).data_link
                if _dl is not None:
                    data_link = _dl
            except Exception:
                pass
        # STAGING: CommMethod resolved via the comment_id link (full Communications).
        comm_method = self._comm_method_from_data_link(data_link)
        extended_properties = self._extended_properties_from_data_collection(data_link)
        # Drive-peripheral modules name their underlying device in
        # UserDefinedCatalogNumber, recovered from the linked device-profile record.
        ud_catalog_number = (self._udcn_from_data_collection(data_link)
                             if ud_vendor is not None else None)

        # Read individual connection records from RxMapConnectionCollection children.
        # Each child's comp_name is the connection Name in the L5X output.
        # Connection Type is inferred from the name (heuristic):
        #   names containing "output" or equal to "config" -> "Output"
        #   all others -> "Input"
        # RPI / Unicast / EventID are decoded from the connection record by
        # _build_connection_map (looked up by the record's object_id); when the
        # record is not a recognised module connection they keep import defaults.
        self._cur.execute(
            "SELECT c2.comp_name, c2.object_id FROM comps c1 "
            "JOIN comps c2 ON c2.parent_id = c1.object_id "
            "WHERE c1.parent_id = ? AND c1.comp_name = 'RxMapConnectionCollection' "
            "ORDER BY c2.seq_number",
            (self._object_id,),
        )
        # A generic-profile or drive module states its connection points and sizes
        # explicitly (the assembly is user-configured); a catalog I/O card omits
        # them (its Module Definition fixes the assembly).
        generic_drive = (
            product_type in _CONN_DIRECT_PRODUCT_TYPES
            or (product_type == 0 and vendor == _CONN_GENERIC_VENDOR)
        )
        # The local chassis / CPU module ("Local") exposes its backplane only as an
        # Output topology record (read above for chassis size/slot), never as a
        # discrete <Connection> -- the reference emits no connections for it -- so
        # skip its connection records (every "Local" module in the reference has an
        # empty <Connections/>).
        conn_rows = [] if name == "Local" else self._cur.fetchall()
        for (conn_name, conn_oid) in conn_rows:
            name_lower = conn_name.lower()
            heuristic_output = "output" in name_lower or name_lower == "config"
            dec = self._conn_decode.get(conn_oid)
            if not dec:
                conn_type = "Output" if heuristic_output else "Input"
                connections.append({
                    "name": conn_name, "type": conn_type, "rpi": "0.0",
                    "unicast": "false", "event_id": "0", "stub_output": heuristic_output,
                })
                continue
            c = {
                "name": conn_name, "type": dec["Type"], "rpi": dec["RPI"],
                "unicast": dec["Unicast"], "event_id": dec["EventID"],
                "stub_output": heuristic_output,
                # A connection with no output/input data carries no Output/InputTag.
                "has_output": dec["OutputSize"] > 0,
                "has_input": dec["InputSize"] > 0,
                # Raw decoded assembly sizes, kept on every decoded connection so the
                # Communications-level PrimCxn*/SecCxn* attributes can read them even
                # when they are not surfaced as Connection size attributes.
                "in_size": dec["InputSize"],
                "out_size": dec["OutputSize"],
                # Motion sync/async/event connections carry no I/O assembly at all
                # (bare <Connection>); MotionDiagnostics is NOT one of these and
                # does carry IO tags, so match the three exact types only.
                "is_motion": dec["Type"] in (
                    "MotionAsync", "MotionEvent", "MotionSync"),
                # Whether Unicast is rendered at all (per-connection-nature).
                "unicast_present": dec.get("_unicast_present", True),
            }
            # Modern data-driven / safety connection attributes (Priority,
            # InputConnectionType, InputProductionTrigger, ConnectionPath, tag
            # suffixes, and the safety timing set). The combined-signature keys ride
            # on every connection so the <Connections> container can find one.
            for _k in ("_connections_signature", "_connections_signature_ts"):
                if _k in dec:
                    c[_k] = dec[_k]
            # Per-connection data-driven / safety attributes. Auto-named raw
            # connections (comp_name "_<pathhex>") carry the same
            # ConnectionPath/Priority/connection-type/timing attributes in the
            # reference; only their InputTagSuffix/OutputTagSuffix follow a
            # per-module backing-tag rule the path decode does not capture (the
            # path-instance suffix heuristic mis-resolves them), so those two are
            # withheld for auto-named connections rather than emitted with a wrong
            # value.
            _modern_keys = ["Priority", "InputConnectionType", "InputProductionTrigger",
                            "ConnectionPath", "TimeoutMultiplier", "NetworkDelayMultiplier",
                            "MaxObservedNetworkDelay", "ReactionTimeLimit",
                            "SafetySignature", "SafetySignatureTimestamp"]
            if not conn_name.startswith("_"):
                _modern_keys += ["InputTagSuffix", "OutputTagSuffix"]
            for _k in _modern_keys:
                if _k in dec:
                    c[_k] = dec[_k]
            fmt = dec["fmt"]
            direct = fmt == _CONN_FMT_OUTPUT and generic_drive
            if fmt in (48, 49) or direct:
                c["InputSize"] = dec["InputSize"]
            if fmt in (48, 50) or direct:
                c["OutputSize"] = dec["OutputSize"]
            if direct:
                c["InputCxnPoint"] = dec["InputCxnPoint"]
                c["OutputCxnPoint"] = dec["OutputCxnPoint"]
            connections.append(c)

        # CatalogNumber: prefer the (V,PT,PC,Major) override for hardware-revision
        # ambiguous keys, then the (V,PT,PC) base table; finally fall back to any
        # <CatNum> carried in the harvested ExtendedProperties XML.
        catalog_number = CATALOG_NUMBERS_BY_MAJOR.get(
            (vendor, product_type, product_code, major)
        )
        if not catalog_number:
            catalog_number = CATALOG_NUMBERS.get(
                (vendor, product_type, product_code), ""
            )
        if not catalog_number and extended_properties:
            try:
                _cm = re.search(r"<CatNum>([^<]+)</CatNum>", extended_properties)
                if _cm:
                    catalog_number = _cm.group(1)
            except Exception:
                pass

        # ConfigTag / InputTag / OutputTag content: a module's <Communications> tags
        # carry the same <Data> as its controller config (:C), input (:I) and output
        # (:O) tags (verified byte-identical; and the reference's ConfigTag set equals
        # its set of :C config tags). Those tags are stored as &<parentOid>:<slot>:X
        # (slotted card) or &<selfOid>:X (Ethernet device); resolving the owner by
        # object_id rather than the friendly parent name avoids the slot collision a
        # mis-parented motion axis would otherwise cause. Try the Ethernet (self) key
        # first, then the slotted (parent, slot) key.
        config_inner = None
        config_size = None
        input_inner = None
        output_inner = None
        safety_output_inner = None
        status_inner = None
        rack_has_input = False
        rack_has_output = False
        entry = self._io_map.get((self._object_id, None))
        parent_oid = None
        if entry is None:
            parent_oid = self._modid_to_oid.get(parent_modid)
            if parent_oid is not None:
                entry = self._io_map.get((parent_oid, slot))
        if entry is None and parent_oid is None and parent_name:
            # Fallback: the &<parentOid>:<slot>:C/I/O tags are keyed by the parent
            # module's comps object_id. When parent_modid does not resolve through
            # modid_to_oid at all, resolve the friendly parent name to its object_id
            # and try that (oid, slot). This is only safe when the parent was NOT
            # resolved: if parent_modid DID resolve to a real parent that simply owns
            # no :C for this slot (a DeviceNet bridge / sub-chassis device, or a
            # module named "Local" that is itself a bridge), the module genuinely has
            # no ConfigTag -- grabbing a same-slot :C from a different module named
            # "Local" would fabricate one.
            prow = self._cur.execute(
                "SELECT object_id FROM comps WHERE comp_name=? AND record_type=256",
                (parent_name,)).fetchone()
            if prow is not None and prow[0] != self._object_id:
                entry = self._io_map.get((prow[0], slot))
        if entry is not None:
            cfg = entry.get("C")
            if cfg is not None:
                config_inner, config_size = cfg
            # A module owns one input family: plain :I, safety :SI, or IO-Link :I1
            # (never mixed). A standard output uses :O/:O1; a safety output uses the
            # separate :SO tag (chosen per-connection in Module.to_xml by type).
            input_inner = entry.get("I") or entry.get("SI") or entry.get("I1")
            output_inner = entry.get("O") or entry.get("O1")
            safety_output_inner = entry.get("SO")
            status_inner = entry.get("S")
            rack_has_input = bool(entry.get("has_I"))
            rack_has_output = bool(entry.get("has_O"))

            # InputTagSuffix / OutputTagSuffix for the module's auto-named data-driven
            # connections: the path decode cannot resolve them, but the module's own
            # backing I/O tag suffixes can. The captured tag suffixes, sorted, map 1:1
            # in connection order to the auto-named data-driven connections (validated
            # against the reference: on every such module the ordered connection
            # suffixes equal the sorted backing-tag suffixes). Assigned only when the
            # counts align, so a partially-captured module under-emits rather than
            # mislabels.
            _auto_dd = [cc for cc in connections
                        if cc["name"].startswith("_") and "ConnectionPath" in cc]
            if _auto_dd:
                _in_sfx = sorted(k for k in entry if k in ("I", "I1", "I2"))
                _out_sfx = sorted(k for k in entry if k in ("O", "O1", "O2"))
                # Order connections by name (the path hex, which encodes the
                # ascending assembly connection points) so the I1/I2 numbering lines
                # up with the reference's, independent of record sequence order.
                _in_conns = sorted((cc for cc in _auto_dd if cc.get("in_size", 0) > 0),
                                   key=lambda cc: cc["name"])
                _out_conns = sorted((cc for cc in _auto_dd if cc.get("out_size", 0) > 0),
                                    key=lambda cc: cc["name"])
                if len(_in_conns) == len(_in_sfx):
                    for cc, sfx in zip(_in_conns, _in_sfx):
                        cc["InputTagSuffix"] = sfx
                if len(_out_conns) == len(_out_sfx):
                    for cc, sfx in zip(_out_conns, _out_sfx):
                        cc["OutputTagSuffix"] = sfx

        # <ConfigData>/<ConfigScript>: a module with a config image but NO controller
        # :C tag (mutually exclusive with ConfigTag) carries the image as a raw
        # <ConfigData> plus an optional <ConfigScript>. The image lives in a hash-named
        # RxDataCollection holder the module points at by object id. Resolve the holder,
        # read its image, derive ConfigSize/Size, and guard with a sanity bound so a
        # stray short-header pointer never emits a garbage size. Only attempted when no
        # ConfigTag was found for this module (config_inner is None).
        configdata = None   # (hex_data, ConfigSize)
        configscript = None  # (hex_data, Size)
        if config_inner is None and (self._cfg_by_mr28 or self._cfg_pool):
            # ConfigData holder: long-header via e1[0x20:0x24] -> holder main_record@0x28;
            # short-header via the 16-byte trailer before the identity marker (object id
            # at marker-12 .. marker-8), falling back to e1[624:628].
            cd_oid = None
            if self._short_header:
                mk = raw_rec.find(_CONFIG_MARK)
                if mk >= 12:
                    cand = struct.unpack_from("<I", raw_rec, mk - 8)[0]
                    if cand in self._cfg_pool:
                        cd_oid = cand
                if cd_oid is None and mi.config_data_oid is not None:
                    if mi.config_data_oid in self._cfg_pool:
                        cd_oid = mi.config_data_oid
            elif mi.config_ref is not None:
                cd_oid = self._cfg_by_mr28.get(mi.config_ref)
            # A PowerFlex 753-NET-E drive (product_type 123) carries a config image
            # the reference renders ONLY as <ConfigScript> (a parameter-download
            # script), never as <ConfigData> -- so resolve its script below but skip
            # ConfigData. Verified pool-wide: every product_type 123 module is
            # ConfigScript-only, and 123 is the only type that is uniformly so.
            if cd_oid is not None and product_type != _CONFIGSCRIPT_ONLY_PT:
                img = _config_holder_image(self._cur, cd_oid, self._short_header)
                if img is not None and len(img) >= 4:
                    csize = struct.unpack_from("<I", img, 0)[0] - 4
                    if 0 <= csize <= _CONFIG_IMG_MAX:
                        configdata = (_tag_value.render_hex(img), csize)
            # ConfigScript holder: comment_id at e1[556:558] -> holder; Size = image len.
            if mi.config_script_cid is not None:
                cs_cid = mi.config_script_cid
                cs_oid = self._cfg_by_cid.get(cs_cid) if cs_cid else None
                if cs_oid is not None:
                    img = _config_holder_image(self._cur, cs_oid, self._short_header)
                    if img is not None and 0 < len(img) <= _CONFIG_IMG_MAX:
                        configscript = (_tag_value.render_hex(img), len(img))

        # Fallbacks for residual modules the pointer rules above miss. ConfigData: the
        # module's ext-attr 0x13e (surfaced only by read_value_attrs on the full record)
        # is the holder object id directly. ConfigScript: a comment_id inside the e1
        # `20 6a` TLV resolves to a holder via the same cid index. Both read the holder
        # image via its ext-attr 0x66. Only run when no ConfigTag was found (mutually
        # exclusive) and the primary rule left the slot unresolved.
        # The ConfigScript `20 6a` resolution runs regardless of config_inner so a
        # module that ALSO owns a ConfigTag still recovers its script (ConfigScript
        # and the script are not mutually exclusive); the ConfigData fallback stays
        # gated on config_inner (mutually exclusive with ConfigTag).
        if configscript is None or (config_inner is None and configdata is None):
            # Reads full=False (not record_attrs) deliberately.
            self._cur.execute(
                "SELECT record FROM comps WHERE object_id=?", (self._object_id,))
            _mr = self._cur.fetchone()
            if _mr:
                try:
                    _ma = CompsRecord.read_value_attrs(bytes(_mr[0]), self._short_header,
                                                       body_mode=True)
                except Exception:
                    _ma = {}
                # The 0x13e fallback is a speculative recovery, used only when the
                # reliable primary pointer found nothing. A communications-adapter
                # module (product_type 12: EN/DeviceNet bridges, scanners) that has
                # real config reaches it through the primary pointer; a missing
                # primary there means "no config", so do not speculate -- the 0x13e
                # ext-attr on these resolves to a generic image the reference does
                # not render as <ConfigData>.
                if (config_inner is None and configdata is None
                        and product_type not in (12, _CONFIGSCRIPT_ONLY_PT)):
                    _ref = _ma.get(0x13E)
                    if _ref and len(_ref) == 4:
                        img = _config_holder_image(
                            self._cur, struct.unpack("<I", _ref)[0], self._short_header)
                        if img is not None and len(img) >= 4:
                            u = struct.unpack_from("<I", img, 0)[0] - 4
                            csize = u if 0 <= u <= _CONFIG_IMG_MAX else len(img)
                            configdata = (_tag_value.render_hex(img), csize)
                if configscript is None:
                    _e1f = _ma.get(0x001) or e1
                    j = _e1f.find(b"\x20\x6a")
                    if j >= 0 and len(_e1f) >= j + 5:
                        sel = _e1f[j + 2]
                        deltas = (3,) if sel == 0x24 else (4,) if sel == 0x25 else (3, 4)
                        for _d in deltas:
                            if len(_e1f) < j + _d + 2:
                                continue
                            cid = struct.unpack_from("<H", _e1f, j + _d)[0]
                            oid = self._cfg_by_cid.get(cid) if cid else None
                            if oid is None:
                                continue
                            img = _config_holder_image(self._cur, oid, self._short_header)
                            if img is not None and 0 < len(img) <= _CONFIG_IMG_MAX:
                                configscript = (_tag_value.render_hex(img), len(img))
                                break

        # Project-level OPC UA flag (see ExportL5x.project_flags); same pattern as
        # TagBuilder. When the project's OPC UA server is on, module IO tag stubs
        # carry OpcUaAccess="None".
        try:
            self._cur.execute("SELECT opc_ua FROM project_flags")
            _pf = self._cur.fetchone()
            _opc_ua = bool(_pf[0]) if _pf else False
        except Exception:
            _opc_ua = False

        # Real port topology from the RxDataCollection blob (preferred over the
        # static catalog). e1[0x24] is the comment_id of the module's backing
        # RxDataCollection child (a 1:1 link); None when it has no <in> blob.
        # The root controller is decoded the same way: its data_link is recovered
        # from comps_full (above) and the full <in> blob from the child's decrypted
        # 0x66 image when the plaintext body is truncated. _ports_from_data_collection
        # returns None when there is no blob (e.g. a 5069 root with a degenerate
        # data_link), so such roots still fall back to the static catalog / empty.
        is_root = (parent_name == name)
        # The root and the conventionally-named controller-chassis modules
        # ("Local"/"Local2") must decode to a controller-type backplane port; gate
        # their blob on that so a mis-linked I/O-adapter blob can't masquerade as the
        # CPU (see _ports_from_data_collection._finish).
        ports_override = self._ports_from_data_collection(
            data_link, validate_controller=(is_root or name in ("Local", "Local2")))

        # SafetyEnabled="true" iff the module owns a safety connection (a
        # SafetyInput/SafetyOutput/*Safety* connection record under its
        # RxMapConnectionCollection). Non-safety modules omit the attribute.
        self._cur.execute(
            "SELECT 1 FROM comps coll JOIN comps o ON o.parent_id = coll.object_id "
            "WHERE coll.parent_id = ? AND coll.comp_name = 'RxMapConnectionCollection' "
            "AND o.comp_name LIKE '%Safety%' LIMIT 1",
            (self._object_id,),
        )
        safety_enabled = self._cur.fetchone() is not None

        # Drive ADC + Safety Network Number live in the FULL identity ext-attr 0x001
        # (read from comps_full; the record copy can be truncated before these
        # offsets). A drive module's 0x001 starts with the class word 0x0200; the
        # ADC bits are the u32 before its lone 0xFFFFFFFF sentinel (bit 6 = Enabled,
        # bit 1 = Mode). The 6-byte little-endian Safety Network Number is at offset
        # 305, present (high byte nonzero) only on a safety module.
        drives_adc_enabled = drives_adc_mode = safety_network = None
        safety_signature = safety_signature_timestamp = None
        try:
            _fe1 = CompsRecord.record_attrs(
                self._cur, self._object_id, self._short_header).get(0x001, b"")
            _fmi = ModuleIdentity.from_bytes(_fe1)
            if _fmi.class_word in (0x0200, 0x0201):
                _p = _fe1.find(b"\xff\xff\xff\xff")
                _v = struct.unpack_from("<I", _fe1, _p - 4)[0] if _p >= 4 else 0
                drives_adc_enabled = "true" if (_v & 0x40) else "false"
                drives_adc_mode = "true" if (_v & 0x02) else "false"
            if _fmi.safety_network is not None and _fmi.safety_network[5] != 0:
                _be = _fmi.safety_network[::-1].hex()
                safety_network = f"16#0000_{_be[0:4]}_{_be[4:8]}_{_be[8:12]}"
        except Exception:
            pass
        # SafetySignature: join the GSS side table by the module's object type /
        # comment id; a signed controller's Local module carries the all-zero hash.
        try:
            _mrow = self._cur.execute(
                "SELECT record FROM comps WHERE object_id=?",
                (self._object_id,)).fetchone()
            if _mrow and _mrow[0] is not None and len(bytes(_mrow[0])) >= 16:
                _mr = bytes(_mrow[0])
                _sr = safety_signature_row(self._cur, _mr)
                if _sr and _sr[0]:
                    safety_signature = _sr[0]
                    safety_signature_timestamp = _sr[1]
                elif name == "Local":
                    _sc = self._cur.execute(
                        "SELECT record FROM comps WHERE comp_name='SafetyController' "
                        "AND record_type=256 LIMIT 1").fetchone()
                    if _sc and _sc[0] is not None and len(bytes(_sc[0])) >= 16:
                        _scr = bytes(_sc[0])
                        _ck = (struct.unpack_from("<H", _scr, 0x0A)[0],
                               struct.unpack_from("<I", _scr, 0x0C)[0])
                        _csr = self._cur.execute(
                            "SELECT timestamp FROM safety_signatures WHERE otype=? AND "
                            "cid=? AND signature IS NOT NULL", _ck).fetchone()
                        if _csr:
                            safety_signature = " - ".join(["00000000"] * 8)
                            safety_signature_timestamp = _csr[0]
        except Exception:
            pass

        return Module(
            name,           # L5xElement._name (private)
            name,           # Module.name
            catalog_number,
            vendor,
            product_type,
            product_code,
            major,
            minor,
            parent_name,
            # The root controller module always references backplane port 1; its
            # identity record sometimes stores a different upstream port id (seen as
            # 2 on a subset of projects). Verified 116/116 roots = 1 vs OEM.
            1 if is_root else parent_port,
            inhibited,
            major_fault,
            _is_root=is_root,
            _class_word=class_word,
            _product_type=product_type,
            _modid=mi.modid,
            _ekey_state=ekey_state,
            _slot=slot,
            _ip_address=ip_address,
            _backplane_slot=backplane_slot,
            _chassis_size=chassis_size,
            _ports_override=ports_override,
            _description=description,
            _comm_method=comm_method,
            _connections=connections,
            _extended_properties=extended_properties,
            _opc_ua=_opc_ua,
            _config_inner=config_inner,
            _config_size=config_size,
            _input_inner=input_inner,
            _output_inner=output_inner,
            _safety_output_inner=safety_output_inner,
            _status_inner=status_inner,
            _rack_has_input=rack_has_input,
            _rack_has_output=rack_has_output,
            _safety_enabled=safety_enabled,
            _config_data=configdata,
            _config_script=configscript,
            _drives_adc_enabled=drives_adc_enabled,
            _drives_adc_mode=drives_adc_mode,
            _safety_network=safety_network,
            _safety_signature=safety_signature,
            _safety_signature_timestamp=safety_signature_timestamp,
            _ud_vendor=ud_vendor,
            _ud_product_type=ud_product_type,
            _ud_product_code=ud_product_code,
            _ud_major=ud_major,
            _ud_minor=ud_minor,
            _ud_catalog_number=ud_catalog_number,
            _shutdown_parent_on_fault=shutdown_parent_on_fault,
        )
