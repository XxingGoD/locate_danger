import json
import re

import idaapi
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_name
import ida_nalt
import ida_netnode
import ida_dbg
import ida_ua
import ida_xref
import idautils


PLUGIN_NAME = "Locatespace"
LOG_PREFIX = "[Locatespace] "
RULES_NODE_NAME = "$ locatespace.rules"
RULES_BLOB_TAG = "L"
RULES_BLOB_INDEX = 0
DEFAULT_RULE_CATEGORY = "custom"
DEFAULT_RULE_SEVERITY = "high"
MENU_NAME = "locatespace_menu"
MENU_LABEL = "Locatespace"
MENU_INSERT_BEFORE = "View"
MENU_PATH_CANDIDATES = (
    "Locatespace",
    "Locatespace/",
    "Edit/Plugins/",
    "Edit/Plugins",
)
ACTION_SCAN = "locatespace:scan"
ACTION_EDIT_RULES = "locatespace:edit_rules"
ACTION_DISABLE = "locatespace:disable"
ACTION_ENABLE = "locatespace:enable"
SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def log(message):
    ida_kernwin.msg(f"{LOG_PREFIX}{message}\n")


class DangerRuleManager:
    """
    Maintain the dangerous function catalog and provide name normalization.

    The normalization step is intentionally conservative. The goal is to
    collapse common import/thunk variants to the canonical libc/API name
    without being overly aggressive and introducing false positives.
    """

    def __init__(self):
        self.rules = {}
        self.alias_map = {
            "__isoc99_sscanf": "sscanf",
            "__isoc99_scanf": "scanf",
            "__isoc99_fscanf": "fscanf",
            "__libc_system": "system",
        }

    def import_rules(self, raw_rules):
        normalized_rules = {}

        if not isinstance(raw_rules, dict):
            return

        for name, rule in raw_rules.items():
            normalized_name = self.normalize_name(name)
            if not normalized_name:
                continue

            if not isinstance(rule, dict):
                rule = {}

            category = str(rule.get("category", DEFAULT_RULE_CATEGORY)).strip() or DEFAULT_RULE_CATEGORY
            severity = str(rule.get("severity", DEFAULT_RULE_SEVERITY)).strip().lower() or DEFAULT_RULE_SEVERITY
            if severity not in SEVERITY_RANK:
                severity = DEFAULT_RULE_SEVERITY

            normalized_rules[normalized_name] = {
                "category": category,
                "severity": severity,
            }

        self.rules = normalized_rules

    def export_rules(self):
        return {
            name: {
                "category": rule["category"],
                "severity": rule["severity"],
            }
            for name, rule in sorted(self.rules.items())
        }

    def normalize_name(self, name):
        if not name:
            return ""

        normalized = ida_lines.tag_remove(str(name)).strip()
        if not normalized:
            return ""

        if normalized in self.alias_map:
            return self.alias_map[normalized]

        if normalized.endswith("@plt"):
            normalized = normalized[:-len("@plt")]

        if normalized.startswith("__imp_"):
            normalized = normalized[len("__imp_"):]

        if normalized.startswith("imp_"):
            normalized = normalized[len("imp_"):]

        # Import stubs and compiler-added wrappers often carry one or more
        # leading underscores. Keep stripping until the name stabilizes.
        while normalized.startswith("_"):
            normalized = normalized[1:]

        if normalized.startswith("j_"):
            normalized = normalized[len("j_"):]

        if normalized in self.alias_map:
            normalized = self.alias_map[normalized]

        return normalized

    def match_name(self, raw_name):
        normalized = self.normalize_name(raw_name)
        if normalized not in self.rules:
            return None

        rule = self.rules[normalized]
        return {
            "original_name": raw_name,
            "normalized_name": normalized,
            "category": rule["category"],
            "severity": rule["severity"],
        }

    def build_line_markers(self, original_name, normalized_name):
        """
        Build a small set of textual markers used for pseudocode highlighting.

        Hex-Rays may print the canonical function name, a thunk name, or a
        lightly transformed variant. Keeping multiple candidate spellings here
        improves the chance of matching the rendered pseudocode line.
        """

        markers = set()
        for candidate in (original_name, normalized_name):
            if not candidate:
                continue
            plain = ida_lines.tag_remove(str(candidate)).strip()
            if not plain:
                continue
            markers.add(plain)
            markers.add(self.normalize_name(plain))
            if plain.endswith("@plt"):
                markers.add(plain[:-len("@plt")])
        markers.discard("")
        return markers


class DangerCallScanner:
    """
    Scan the database for dangerous function targets and their callers.
    """

    def __init__(self, rule_manager):
        self.rule_manager = rule_manager

    def collect(self):
        direct_targets = self._collect_targets()
        targets = self._expand_wrapper_targets(direct_targets)
        calls = []
        calls_by_func = {}
        seen_calls = set()

        for target in targets:
            for xref in idautils.XrefsTo(target["ea"], 0):
                if not self._is_probably_call_xref(xref):
                    continue

                caller = ida_funcs.get_func(xref.frm)
                if caller is None:
                    continue

                call_key = (xref.frm, caller.start_ea, target["normalized_name"])
                if call_key in seen_calls:
                    continue
                seen_calls.add(call_key)

                caller_name = ida_name.get_name(caller.start_ea) or f"sub_{caller.start_ea:X}"
                call_info = {
                    "callsite_ea": xref.frm,
                    "caller_func_ea": caller.start_ea,
                    "caller_func_name": caller_name,
                    "callee_ea": target["ea"],
                    "callee_original_name": target["original_name"],
                    "callee_normalized_name": target["normalized_name"],
                    "risk_category": target["category"],
                    "severity": target["severity"],
                    "source": target["source"],
                    "line_markers": self.rule_manager.build_line_markers(
                        target["original_name"], target["normalized_name"]
                    ),
                    "summary": self._build_call_summary(xref.frm, target),
                }

                calls.append(call_info)
                calls_by_func.setdefault(caller.start_ea, []).append(call_info)

        return targets, calls, calls_by_func

    def _collect_targets(self):
        results = []
        seen_eas = set()

        for item in self._collect_from_imports():
            if item["ea"] in seen_eas:
                continue
            seen_eas.add(item["ea"])
            results.append(item)

        for item in self._collect_from_functions():
            if item["ea"] in seen_eas:
                continue
            seen_eas.add(item["ea"])
            results.append(item)

        return results

    def _collect_from_imports(self):
        results = []
        module_count = ida_nalt.get_import_module_qty()

        for module_index in range(module_count):
            module_name = ida_nalt.get_import_module_name(module_index) or f"import_{module_index}"

            def import_callback(ea, name, ordinal):
                if not name:
                    return True

                match = self.rule_manager.match_name(name)
                if match is None:
                    return True

                results.append(
                    {
                        "ea": ea,
                        "original_name": match["original_name"],
                        "normalized_name": match["normalized_name"],
                        "category": match["category"],
                        "severity": match["severity"],
                        "source": "import",
                        "module_name": module_name,
                        "ordinal": ordinal,
                    }
                )
                return True

            ida_nalt.enum_import_names(module_index, import_callback)

        return results

    def _collect_from_functions(self):
        results = []

        for func_ea in idautils.Functions():
            func_name = ida_name.get_name(func_ea)
            if not func_name:
                continue

            match = self.rule_manager.match_name(func_name)
            if match is None:
                continue

            results.append(
                {
                    "ea": func_ea,
                    "original_name": match["original_name"],
                    "normalized_name": match["normalized_name"],
                    "category": match["category"],
                    "severity": match["severity"],
                    "source": "function",
                }
            )

        return results

    def _is_probably_call_xref(self, xref):
        xref_type = getattr(xref, "type", None)
        return xref_type in (ida_xref.fl_CF, ida_xref.fl_CN)

    def _expand_wrapper_targets(self, base_targets):
        """
        Expand direct dangerous targets to include simple thunk/wrapper entrypoints.

        Typical cases:
        - ELF PLT or import thunks
        - Compiler-generated jump stubs
        - Thin local wrappers that only tail-call the sink

        The wrapper inherits the same risk metadata as the real dangerous target.
        This keeps downstream call collection unchanged while improving coverage.
        """

        expanded = []
        queue = []
        seen = set()

        for target in base_targets:
            expanded.append(target)
            queue.append(target)
            seen.add(target["ea"])

        while queue:
            current = queue.pop(0)
            for wrapper in self._find_simple_wrappers_to(current):
                wrapper_ea = wrapper["ea"]
                if wrapper_ea in seen:
                    continue
                seen.add(wrapper_ea)
                expanded.append(wrapper)
                queue.append(wrapper)

        return expanded

    def _find_simple_wrappers_to(self, target):
        """
        Find named functions that reference the target and look like thunks or
        very small wrappers. This intentionally stays conservative.
        """

        wrappers = []
        seen_wrapper_eas = set()

        for xref in idautils.XrefsTo(target["ea"], 0):
            wrapper_func = ida_funcs.get_func(xref.frm)
            if wrapper_func is None:
                continue

            wrapper_ea = wrapper_func.start_ea
            if wrapper_ea == target["ea"]:
                continue
            if wrapper_ea in seen_wrapper_eas:
                continue

            if not self._looks_like_wrapper(wrapper_func, target["ea"]):
                continue

            seen_wrapper_eas.add(wrapper_ea)
            wrapper_name = ida_name.get_name(wrapper_ea) or f"sub_{wrapper_ea:X}"
            wrappers.append(
                {
                    "ea": wrapper_ea,
                    "original_name": wrapper_name,
                    "normalized_name": target["normalized_name"],
                    "category": target["category"],
                    "severity": target["severity"],
                    "source": "wrapper",
                    "real_target_ea": target["ea"],
                }
            )

        return wrappers

    def _looks_like_wrapper(self, func, target_ea):
        """
        Conservative wrapper heuristic.

        Accept:
        - IDA-marked thunk functions
        - Very small functions with a single call/jump out to the target

        Reject:
        - Larger functions that likely perform meaningful work
        - Functions with multiple call sites
        """

        flags = getattr(func, "flags", 0)
        if flags & ida_funcs.FUNC_THUNK:
            return True

        item_count = 0
        outbound_calls = 0
        references_target = False

        for ea in idautils.FuncItems(func.start_ea):
            item_count += 1

            for ref_to in idautils.CodeRefsFrom(ea, 0):
                callee = self._resolve_callee_entry(ref_to)
                if callee is None:
                    continue

                outbound_calls += 1
                if callee == target_ea:
                    references_target = True

            # Keep the wrapper heuristic intentionally small to reduce
            # accidental promotion of normal helper functions.
            if item_count > 12 or outbound_calls > 2:
                return False

        if not references_target:
            return False

        return outbound_calls <= 2

    def _resolve_callee_entry(self, ref_to):
        """
        Normalize a code reference target to the containing function entry when
        possible, so that callsites landing inside PLT/import stubs still map to
        the wrapper function start.
        """

        func = ida_funcs.get_func(ref_to)
        if func is not None:
            return func.start_ea
        return ref_to

    def _build_call_summary(self, callsite_ea, target):
        """
        Build a compact human-facing summary for result browsing.

        First preference is the rendered disassembly line around the callsite,
        because it is always available. This keeps the chooser useful even
        before a function is decompiled.
        """

        disasm = self._get_disasm_summary(callsite_ea)
        if disasm:
            return disasm

        return "{}(...)".format(target["normalized_name"])

    def _get_disasm_summary(self, ea):
        try:
            line = ida_lines.generate_disasm_line(ea, 0)
        except Exception:
            line = None

        if not line:
            return ""

        text = ida_lines.tag_remove(line).strip()
        if not text:
            return ""

        text = re.sub(r"\s+", " ", text)
        if len(text) > 96:
            text = text[:93] + "..."
        return text


class DangerState:
    """
    Hold scan results and expose helpers used by the UI/highlighting layer.
    """

    def __init__(self):
        self.rule_manager = DangerRuleManager()
        self.scanner = DangerCallScanner(self.rule_manager)
        self.targets = []
        self.calls = []
        self.calls_by_func = {}
        self.function_rows = []
        self.enabled = True
        self.minimum_severity = "low"
        self.plugin_breakpoints = set()
        self.chooser = None
        self.rule_chooser = None
        self._load_rules_from_idb()

    def rescan(self):
        self._clear_plugin_breakpoints()
        self.targets, self.calls, self.calls_by_func = self.scanner.collect()
        self.function_rows = self._build_function_rows()
        self._apply_plugin_breakpoints()
        self._log_summary()

    def has_rules(self):
        return bool(self.rule_manager.rules)

    def show_rule_manager(self):
        if self.rule_chooser is None:
            self.rule_chooser = DangerRuleChooser(self)
        return self.rule_chooser.Show()

    def prompt_rule(self, initial_name="", initial_category=DEFAULT_RULE_CATEGORY, initial_severity=DEFAULT_RULE_SEVERITY):
        return RuleEditorForm.ask(initial_name, initial_category, initial_severity, self.rule_manager)

    def add_or_update_rule(self, name, category, severity, previous_name=None):
        normalized_name = self.rule_manager.normalize_name(name)
        if not normalized_name:
            ida_kernwin.warning("Function name is empty")
            return False

        if severity not in SEVERITY_RANK:
            ida_kernwin.warning("Invalid severity")
            return False

        rules = self.rule_manager.export_rules()
        if previous_name:
            previous_normalized = self.rule_manager.normalize_name(previous_name)
            if previous_normalized and previous_normalized != normalized_name:
                rules.pop(previous_normalized, None)

        rules[normalized_name] = {
            "category": category or DEFAULT_RULE_CATEGORY,
            "severity": severity,
        }
        self.rule_manager.import_rules(rules)
        self._save_rules_to_idb()
        log(f"updated dangerous function list: {len(self.rule_manager.rules)} rules")
        return True

    def remove_rule(self, name):
        normalized_name = self.rule_manager.normalize_name(name)
        if not normalized_name:
            return False

        rules = self.rule_manager.export_rules()
        if normalized_name not in rules:
            return False

        del rules[normalized_name]
        self.rule_manager.import_rules(rules)
        self._save_rules_to_idb()
        log(f"removed dangerous function: {normalized_name}")
        return True

    def get_rule_rows(self):
        rows = []
        for name, rule in sorted(self.rule_manager.export_rules().items()):
            rows.append(
                {
                    "name": name,
                    "category": rule["category"],
                    "severity": rule["severity"],
                }
            )
        return rows

    def get_calls_for_function(self, func_ea):
        return self.calls_by_func.get(func_ea, [])

    def get_all_calls(self):
        return [
            call for call in self.calls
            if SEVERITY_RANK.get(call["severity"], 0) >= SEVERITY_RANK.get(self.minimum_severity, 0)
        ]

    def get_all_functions(self):
        threshold = SEVERITY_RANK.get(self.minimum_severity, 0)
        rows = []
        for row in self.function_rows:
            if SEVERITY_RANK.get(row["max_severity"], 0) >= threshold:
                rows.append(row)
        return rows

    def refresh_current_pseudocode(self):
        widget = ida_kernwin.get_current_widget()
        if widget is None:
            return

        if ida_kernwin.get_widget_type(widget) != ida_kernwin.BWN_PSEUDOCODE:
            return

        vu = ida_hexrays.get_widget_vdui(widget)
        if vu is None:
            return

        try:
            vu.refresh_view(True)
        except Exception:
            ida_kernwin.refresh_idaview_anyway()

    def disable(self):
        self.enabled = False
        self._clear_plugin_breakpoints()
        self.targets = []
        self.calls = []
        self.calls_by_func = {}
        self.function_rows = []
        self.refresh_current_pseudocode()
        self.close_choosers()
        log("plugin disabled")

    def enable(self):
        self.enabled = True
        self.refresh_current_pseudocode()
        log("plugin enabled")

    def close_choosers(self):
        if self.chooser is not None:
            try:
                self.chooser.Close()
            except Exception:
                pass

        if self.rule_chooser is not None:
            try:
                self.rule_chooser.Close()
            except Exception:
                pass

    def _apply_plugin_breakpoints(self):
        for call in self.calls:
            ea = call["callsite_ea"]
            if self._has_existing_breakpoint(ea):
                continue
            try:
                if ida_dbg.add_bpt(ea, 0, ida_dbg.BPT_DEFAULT):
                    self.plugin_breakpoints.add(ea)
                    continue
            except Exception:
                pass

            # Fallback path for IDA versions/builds where the simple add_bpt
            # overload is not enough for code locations in the current segment.
            try:
                bpt = ida_dbg.bpt_t()
                bpt.ea = ea
                bpt.type = ida_dbg.BPT_DEFAULT
                bpt.size = 0
                if ida_dbg.update_bpt(bpt):
                    self.plugin_breakpoints.add(ea)
            except Exception:
                continue

    def _clear_plugin_breakpoints(self):
        if not self.plugin_breakpoints:
            return

        for ea in list(self.plugin_breakpoints):
            try:
                ida_dbg.del_bpt(ea)
            except Exception:
                pass

        self.plugin_breakpoints.clear()

    def _has_existing_breakpoint(self, ea):
        try:
            count = ida_dbg.get_bpt_qty()
            for index in range(count):
                bpt = ida_dbg.bpt_t()
                if ida_dbg.getn_bpt(index, bpt) and bpt.ea == ea:
                    return True
        except Exception:
            return False

        return False

    def _log_summary(self):
        if not self.rule_manager.rules:
            log("no dangerous functions configured; use the plugin menu to add them")
            return

        log(
            "scan completed: {} dangerous targets, {} dangerous callsites, {} affected functions".format(
                len(self.targets), len(self.calls), len(self.calls_by_func)
            )
        )
        for call in self.calls:
            log(
                "callsite=0x{:X} caller={} callee={} category={} severity={}".format(
                    call["callsite_ea"],
                    call["caller_func_name"],
                    call["callee_normalized_name"],
                    call["risk_category"],
                    call["severity"],
                )
            )

    def _build_function_rows(self):
        rows = []

        for func_ea, calls in self.calls_by_func.items():
            caller_name = calls[0]["caller_func_name"] if calls else (ida_name.get_name(func_ea) or f"sub_{func_ea:X}")
            max_call = max(calls, key=lambda item: SEVERITY_RANK.get(item["severity"], 0))
            categories = sorted({call["risk_category"] for call in calls})
            summary = self._pick_best_function_summary(calls, max_call)

            rows.append(
                {
                    "func_ea": func_ea,
                    "caller_func_name": caller_name,
                    "call_count": len(calls),
                    "max_severity": max_call["severity"],
                    "categories": ",".join(categories),
                    "summary": summary,
                }
            )

        rows.sort(
            key=lambda row: (
                -SEVERITY_RANK.get(row["max_severity"], 0),
                -row["call_count"],
                row["caller_func_name"].lower(),
            )
        )
        return rows

    def _pick_best_function_summary(self, calls, max_call):
        """
        Use the highest-severity call summary as the function-level preview.
        """

        summary = max_call.get("summary", "") if max_call else ""
        if summary:
            return summary

        if calls:
            fallback = calls[0].get("summary", "")
            if fallback:
                return fallback

        return ""

    def _get_rules_node(self, create=False):
        if create:
            return ida_netnode.netnode(RULES_NODE_NAME, 0, True)
        return ida_netnode.netnode(RULES_NODE_NAME)

    def _load_rules_from_idb(self):
        try:
            node = self._get_rules_node(create=False)
            data = node.getblob(RULES_BLOB_INDEX, RULES_BLOB_TAG)
        except Exception:
            data = None

        if not data:
            self.rule_manager.import_rules({})
            return

        try:
            raw_rules = json.loads(data.decode("utf-8"))
        except Exception as exc:
            log(f"failed to load dangerous function list from IDB: {exc}")
            self.rule_manager.import_rules({})
            return

        self.rule_manager.import_rules(raw_rules)

    def _save_rules_to_idb(self):
        try:
            node = self._get_rules_node(create=True)
            payload = json.dumps(self.rule_manager.export_rules(), sort_keys=True).encode("utf-8")
            node.setblob(payload, RULES_BLOB_INDEX, RULES_BLOB_TAG)
        except Exception as exc:
            log(f"failed to save dangerous function list to IDB: {exc}")


class DangerCallChooser(ida_kernwin.Choose):
    """
    Non-modal result panel for browsing dangerous callsites.
    """

    def __init__(self, state):
        self.state = state
        self.items = []
        columns = [
            ["Callsite", 12],
            ["Caller", 28],
            ["Dangerous Callee", 20],
            ["Category", 18],
            ["Severity", 10],
            ["Source", 10],
            ["Summary", 48],
        ]
        super().__init__(
            "Locatespace Dangerous Calls",
            columns,
            flags=ida_kernwin.Choose.CH_RESTORE | ida_kernwin.Choose.CH_CAN_REFRESH,
            embedded=False,
        )
        self.refresh_items()

    def refresh_items(self):
        self.items = []
        for call in self.state.get_all_calls():
            self.items.append(
                [
                    f"0x{call['callsite_ea']:X}",
                    call["caller_func_name"],
                    call["callee_normalized_name"],
                    call["risk_category"],
                    call["severity"],
                    call["source"],
                    call.get("summary", ""),
                ]
            )

    def Show(self, modal=False):
        self.refresh_items()
        return super().Show(modal)

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnRefresh(self, n):
        self.refresh_items()
        return n

    def OnSelectLine(self, n):
        calls = self.state.get_all_calls()
        if n < 0 or n >= len(calls):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        call = calls[n]
        self._jump_to_call(call)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def _jump_to_call(self, call):
        func_ea = call["caller_func_ea"]
        callsite_ea = call["callsite_ea"]

        try:
            vu = ida_hexrays.open_pseudocode(func_ea, 0)
            if vu is not None:
                try:
                    vu.cfunc = ida_hexrays.decompile(func_ea)
                except Exception:
                    pass
                ida_kernwin.activate_widget(vu.ct, True)
                ida_kernwin.jumpto(callsite_ea)
                return
        except Exception:
            pass

        ida_kernwin.jumpto(callsite_ea)


class RuleEditorForm(ida_kernwin.Form):
    SEVERITY_OPTIONS = ["critical", "high", "medium", "low"]
    CATEGORY_OPTIONS = [
        "custom",
        "buffer_write",
        "format_string",
        "command_exec",
        "memory_copy",
    ]

    def __init__(self, name, category, severity):
        F = ida_kernwin.Form
        category_options = list(self.CATEGORY_OPTIONS)
        if category and category not in category_options:
            category_options.append(category)

        severity_options = list(self.SEVERITY_OPTIONS)
        if severity and severity not in severity_options:
            severity_options.append(severity)
        severity_index = severity_options.index(severity if severity in severity_options else DEFAULT_RULE_SEVERITY)

        F.__init__(
            self,
            r"""
BUTTON YES* Save
BUTTON CANCEL Cancel
Locatespace rule

<Function name:{name}>
<Category:{category}>
<Severity:{severity}>
""",
            {
                "name": F.StringInput(swidth=40),
                "category": F.DropdownListControl(items=category_options, readonly=False, selval=category),
                "severity": F.DropdownListControl(items=severity_options, readonly=True, selval=severity_index),
            },
        )
        self._severity_options = severity_options

    @classmethod
    def ask(cls, name, category, severity, rule_manager):
        normalized_name = rule_manager.normalize_name(name) if name else ""
        initial_name = normalized_name or name
        initial_category = category or DEFAULT_RULE_CATEGORY
        initial_severity = severity or DEFAULT_RULE_SEVERITY

        form = cls(initial_name, initial_category, initial_severity)
        form, _args = form.Compile()
        form.name.value = initial_name
        form.category.value = initial_category
        form.severity.value = form._severity_options.index(initial_severity)
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return None

        selected_name = form.name.value.strip()
        selected_category = (form.category.value or "").strip()
        severity_index = form.GetControlValue(form.severity)
        if not isinstance(severity_index, int) or severity_index < 0 or severity_index >= len(form._severity_options):
            severity_index = form._severity_options.index(initial_severity)
        selected_severity = form._severity_options[severity_index]
        form.Free()

        if not selected_name:
            ida_kernwin.warning("Function name is empty")
            return None

        return {
            "name": selected_name,
            "category": selected_category or DEFAULT_RULE_CATEGORY,
            "severity": selected_severity,
        }


class DangerRuleChooser(ida_kernwin.Choose):
    def __init__(self, state):
        self.state = state
        columns = [
            ["Function", 24],
            ["Category", 18],
            ["Severity", 10],
        ]
        super().__init__(
            "Locatespace Dangerous Functions",
            columns,
            flags=(
                ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_INS
                | ida_kernwin.Choose.CH_CAN_DEL
                | ida_kernwin.Choose.CH_CAN_EDIT
                | ida_kernwin.Choose.CH_CAN_REFRESH
            ),
            embedded=False,
        )

    def _rows(self):
        return self.state.get_rule_rows()

    def Show(self, modal=False):
        return super().Show(modal)

    def force_refresh(self):
        try:
            self.Refresh()
        except Exception:
            pass

    def OnGetSize(self):
        return len(self._rows())

    def OnGetLine(self, n):
        row = self._rows()[n]
        return [row["name"], row["category"], row["severity"]]

    def OnRefresh(self, n):
        return None

    def OnInsertLine(self, sel):
        rule = self.state.prompt_rule()
        if rule is None:
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        if not self.state.add_or_update_rule(rule["name"], rule["category"], rule["severity"]):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        self.force_refresh()
        row_count = len(self._rows())
        return (ida_kernwin.Choose.ALL_CHANGED, max(0, row_count - 1))

    def OnDeleteLine(self, sel):
        rows = self._rows()
        if sel < 0 or sel >= len(rows):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        rule_name = rows[sel]["name"]
        if not self.state.remove_rule(rule_name):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        self.force_refresh()
        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(sel)

    def OnEditLine(self, sel):
        rows = self._rows()
        if sel < 0 or sel >= len(rows):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        current_row = rows[sel]
        current_name = current_row["name"]
        current_category = current_row["category"]
        current_severity = current_row["severity"]
        rule = self.state.prompt_rule(current_name, current_category, current_severity)
        if rule is None:
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        if not self.state.add_or_update_rule(
            rule["name"], rule["category"], rule["severity"], previous_name=current_name
        ):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        self.force_refresh()
        normalized_name = self.state.rule_manager.normalize_name(rule["name"])
        for index, item in enumerate(self._rows()):
            if item["name"] == normalized_name:
                return (ida_kernwin.Choose.ALL_CHANGED, index)

        return (ida_kernwin.Choose.ALL_CHANGED, sel)


class DangerHexraysHooks(ida_hexrays.Hexrays_Hooks):
    """
    Colorize pseudocode lines after decompilation has been printed.

    This is intentionally line-based. It is less precise than ctree item-level
    rendering, but much more robust for a first working version and already
    gives the researcher an immediate visual anchor in the pseudocode view.
    """

    HIGHLIGHT_COLOR = 0x0000FF

    def __init__(self, state):
        super().__init__()
        self.state = state

    def func_printed(self, cfunc):
        try:
            self._apply_highlight(cfunc)
        except Exception as exc:
            log(f"highlight error: {exc}")
        return 0

    def _apply_highlight(self, cfunc):
        if not self.state.enabled:
            return

        func_ea = cfunc.entry_ea
        calls = self.state.get_calls_for_function(func_ea)
        if not calls:
            return

        pseudocode = cfunc.get_pseudocode()
        if pseudocode is None:
            return

        highlighted_lines = self._highlight_by_address(cfunc, pseudocode, calls)
        for line in pseudocode:
            if line in highlighted_lines:
                continue
            plain_line = ida_lines.tag_remove(line.line)
            best_call = self._find_best_call_for_line(plain_line, calls)
            if best_call is None:
                continue

            self._apply_visual_marker(line, best_call, plain_line)

    def _highlight_by_address(self, cfunc, pseudocode, calls):
        """
        Prefer address-driven highlighting when Hex-Rays exposes a stable
        callsite -> ctree item -> pseudocode coordinate mapping.

        This reduces ambiguity for lines containing multiple calls and avoids
        relying purely on rendered text when wrappers rename the callee.
        """

        highlighted = set()
        eamap = None

        try:
            eamap = cfunc.get_eamap()
        except Exception:
            eamap = None

        if eamap is None:
            return highlighted

        for call in calls:
            line_index = self._get_line_index_for_call(cfunc, pseudocode, eamap, call["callsite_ea"])
            if line_index is None:
                continue
            if line_index < 0 or line_index >= len(pseudocode):
                continue

            line = pseudocode[line_index]
            if self._should_replace_existing_marker(line, call):
                self._apply_visual_marker(line, call, ida_lines.tag_remove(line.line))
            highlighted.add(line)

        return highlighted

    def _get_line_index_for_call(self, cfunc, pseudocode, eamap, ea):
        """
        Resolve a callsite address to a pseudocode line index.

        The exact object types exposed by IDAPython vary a bit across IDA
        versions, so this method is defensive and supports a few access forms.
        """

        citems = self._eamap_lookup(eamap, ea)
        if not citems:
            return None

        for citem in citems:
            line_index = self._find_line_for_citem(cfunc, citem)
            if line_index is not None:
                return line_index

        return None

    def _eamap_lookup(self, eamap, ea):
        """
        Best-effort access helper for eamap containers.
        """

        try:
            items = eamap[ea]
            if items:
                return list(items)
        except Exception:
            pass

        try:
            items = eamap.get(ea)
            if items:
                return list(items)
        except Exception:
            pass

        return []

    def _find_line_for_citem(self, cfunc, citem):
        """
        Ask Hex-Rays for the screen coordinates of a ctree item. Different
        versions expose slightly different helper signatures, so probe the most
        common ones in order.
        """

        # Variant 1: find_item_coords(item)
        try:
            coords = cfunc.find_item_coords(citem)
            y = self._extract_y_from_coords(coords)
            if y is not None:
                return y
        except Exception:
            pass

        # Variant 2: find_item_coords(None, item)
        try:
            coords = cfunc.find_item_coords(None, citem)
            y = self._extract_y_from_coords(coords)
            if y is not None:
                return y
        except Exception:
            pass

        return None

    def _extract_y_from_coords(self, coords):
        if coords is None:
            return None

        if isinstance(coords, tuple):
            if len(coords) >= 2 and isinstance(coords[1], int):
                return coords[1]
            if len(coords) >= 1 and isinstance(coords[0], int):
                return coords[0]

        y = getattr(coords, "y", None)
        if isinstance(y, int):
            return y

        lnnum = getattr(coords, "lnnum", None)
        if isinstance(lnnum, int):
            return lnnum

        return None

    def _find_best_call_for_line(self, plain_line, calls):
        """
        Choose the highest-severity dangerous call that appears in this line.

        Matching is textual and deliberately simple:
        - Remove Hex-Rays markup tags
        - Search for "name(" with an optional whitespace gap

        This keeps the implementation stable even when exact ctree-to-line
        mapping is not exposed in a convenient form.
        """

        best_call = None
        best_rank = 0

        for call in calls:
            for marker in call["line_markers"]:
                if not marker:
                    continue

                pattern = r"\b{}\s*\(".format(re.escape(marker))
                if re.search(pattern, plain_line) is None:
                    continue

                rank = SEVERITY_RANK.get(call["severity"], 0)
                if rank > best_rank:
                    best_rank = rank
                    best_call = call

        return best_call

    def _update_call_summary_from_pseudocode(self, call, plain_line):
        """
        Upgrade the chooser summary from raw disassembly to a cleaner pseudocode
        snippet when the line can be matched during rendering.
        """

        if not plain_line:
            return

        summary = re.sub(r"\s+", " ", plain_line.strip())
        if not summary:
            return

        if len(summary) > 120:
            summary = summary[:117] + "..."

        call["summary"] = summary

    def _apply_visual_marker(self, line, call, plain_line):
        """
        Use a fixed red background for dangerous calls.
        """

        self._update_call_summary_from_pseudocode(call, plain_line)
        line.bgcolor = self.HIGHLIGHT_COLOR
        setattr(line, "_locatespace_rank", SEVERITY_RANK.get(call["severity"], 0))

    def _should_replace_existing_marker(self, line, call):
        """
        If multiple dangerous calls map to the same line, keep the highest
        severity color on that line.
        """

        current_rank = getattr(line, "_locatespace_rank", -1)
        new_rank = SEVERITY_RANK.get(call["severity"], 0)
        return new_rank >= current_rank


def create_locatespace_runtime():
    state = DangerState()
    hexrays_hooks = DangerHexraysHooks(state)
    hexrays_hooks.hook()
    chooser = DangerCallChooser(state)
    state.chooser = chooser
    return state, hexrays_hooks, chooser


class LocatespaceActionHandler(ida_kernwin.action_handler_t):
    def __init__(self, callback, update_callback=None):
        super().__init__()
        self.callback = callback
        self.update_callback = update_callback

    def activate(self, ctx):
        self.callback()
        return 1

    def update(self, ctx):
        if self.update_callback is not None:
            return self.update_callback(ctx)
        return ida_kernwin.AST_ENABLE_ALWAYS


class LocateSpacePlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Automatically locate dangerous functions and highlight pseudocode"
    help = "Scan dangerous sinks and highlight them in Hex-Rays pseudocode"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Shift-Alt-D"

    def __init__(self):
        super().__init__()
        self.state = None
        self.hexrays_hooks = None
        self.chooser = None
        self.action_handlers = {}
        self.action_menu_paths = {}

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            log("Hex-Rays is not available, plugin skipped")
            return idaapi.PLUGIN_SKIP

        self.state, self.hexrays_hooks, self.chooser = create_locatespace_runtime()
        self._ensure_menu()
        self._register_actions()
        if self.state.has_rules():
            log("plugin initialized; use the Locatespace menu or Shift-Alt-D to scan dangerous calls")
        else:
            log("plugin initialized; configure dangerous functions from the Locatespace menu first")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        """
        Manual trigger:
        - Rescan dangerous calls
        """
        if self.state is None:
            log("plugin state is not ready")
            return

        if not self.state.has_rules():
            self.state.show_rule_manager()
            if not self.state.has_rules():
                log("scan skipped: dangerous function list is empty")
                return

        self._scan_now()

    def _scan_now(self):
        if self.state is None:
            return
        if not self.state.enabled:
            log("plugin is disabled")
            return

        try:
            self.state.rescan()
            self.state.refresh_current_pseudocode()
            if self.chooser is not None:
                self.chooser.Show()
        except Exception as exc:
            log(f"manual rescan failed: {exc}")

    def edit_rules(self):
        if self.state is None:
            log("plugin state is not ready")
            return
        if not self.state.enabled:
            log("plugin is disabled")
            return

        self.state.show_rule_manager()

    def disable_plugin(self):
        if self.state is None:
            log("plugin state is not ready")
            return
        if not self.state.enabled:
            log("plugin is already disabled")
            return

        self.state.disable()

    def enable_plugin(self):
        if self.state is None:
            log("plugin state is not ready")
            return
        if self.state.enabled:
            log("plugin is already enabled")
            return

        self.state.enable()

    def term(self):
        self._unregister_actions()

        if self.state is not None:
            try:
                self.state.disable()
            except Exception:
                pass

        if self.hexrays_hooks is not None:
            try:
                self.hexrays_hooks.unhook()
            except Exception:
                pass
            self.hexrays_hooks = None

        self.chooser = None
        self.state = None

    def _register_actions(self):
        self._register_action(
            ACTION_SCAN,
            "Locatespace: Scan dangerous calls",
            lambda: self.run(0),
            update_callback=self._update_enabled_only,
        )
        self._register_action(
            ACTION_EDIT_RULES,
            "Locatespace: Edit dangerous functions",
            self.edit_rules,
            update_callback=self._update_enabled_only,
        )
        self._register_action(
            ACTION_DISABLE,
            "Locatespace: Disable plugin",
            self.disable_plugin,
            update_callback=self._update_enabled_only,
        )
        self._register_action(
            ACTION_ENABLE,
            "Locatespace: Enable plugin",
            self.enable_plugin,
            update_callback=self._update_disabled_only,
        )

    def _register_action(self, name, label, callback, update_callback=None):
        ida_kernwin.unregister_action(name)
        handler = LocatespaceActionHandler(callback, update_callback=update_callback)
        desc = ida_kernwin.action_desc_t(name, label, handler)
        if not ida_kernwin.register_action(desc):
            log(f"failed to register action: {name}")
            return

        attached_path = self._attach_action_to_plugins_menu(name)
        if attached_path is None:
            log(f"failed to attach action to menu: {name}")
        else:
            self.action_menu_paths[name] = attached_path

        self.action_handlers[name] = handler

    def _unregister_actions(self):
        for name in (ACTION_SCAN, ACTION_EDIT_RULES, ACTION_DISABLE, ACTION_ENABLE):
            attached_path = self.action_menu_paths.get(name)
            if attached_path is not None:
                try:
                    ida_kernwin.detach_action_from_menu(attached_path, name)
                except Exception:
                    pass

            try:
                ida_kernwin.unregister_action(name)
            except Exception:
                pass

        self.action_handlers.clear()
        self.action_menu_paths.clear()

    def _ensure_menu(self):
        try:
            ida_kernwin.create_menu(MENU_NAME, MENU_LABEL, MENU_INSERT_BEFORE)
        except Exception:
            pass

    def _attach_action_to_plugins_menu(self, name):
        for menu_path in MENU_PATH_CANDIDATES:
            try:
                if ida_kernwin.attach_action_to_menu(menu_path, name, ida_kernwin.SETMENU_APP):
                    return menu_path
            except Exception:
                continue

        return None

    def _update_enabled_only(self, ctx):
        if self.state is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE_ALWAYS if self.state.enabled else ida_kernwin.AST_DISABLE

    def _update_disabled_only(self, ctx):
        if self.state is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE_ALWAYS if not self.state.enabled else ida_kernwin.AST_DISABLE


def PLUGIN_ENTRY():
    return LocateSpacePlugin()


_standalone_runtime = None


def run_locatespace_now():
    global _standalone_runtime

    if not ida_hexrays.init_hexrays_plugin():
        ida_kernwin.warning("Hex-Rays is not available")
        return None

    if _standalone_runtime is None:
        _standalone_runtime = create_locatespace_runtime()

    state, _hexrays_hooks, chooser = _standalone_runtime
    state.rescan()
    state.refresh_current_pseudocode()
    chooser.Show()
    return _standalone_runtime


if __name__ == "__main__":
    run_locatespace_now()
