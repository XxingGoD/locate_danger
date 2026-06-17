import json
import re

import idaapi
import ida_bytes
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
IGNORED_CALLS_NODE_NAME = "$ locatespace.ignored_calls"
IGNORED_CALLS_BLOB_TAG = "L"
IGNORED_CALLS_BLOB_INDEX = 0
DEFAULT_RULE_CATEGORY = "custom"
DEFAULT_RULE_SEVERITY = "high"
DEFAULT_ARG_FILTER = "any"
ARG_FILTER_LABELS = {
    "any": "Any arguments",
    "non_string_args": "Require non-string arguments",
    "first_arg_non_string": "First arg non-string",
    "has_variable_arg": "Any variable/pointer arg",
}
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
ACTION_MANAGE_IGNORED = "locatespace:manage_ignored"
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

        if isinstance(raw_rules, list):
            iterable = []
            for rule in raw_rules:
                if not isinstance(rule, dict):
                    continue
                copied = dict(rule)
                copied["name"] = rule.get("name", "")
                iterable.append(copied)
        elif isinstance(raw_rules, dict):
            iterable = []
            for name, rule in raw_rules.items():
                if not isinstance(rule, dict):
                    rule = {}
                copied = dict(rule)
                copied["name"] = name
                iterable.append(copied)
        else:
            self.rules = {}
            return

        for raw_rule in iterable:
            if not isinstance(raw_rule, dict):
                continue

            normalized_name = self.normalize_name(raw_rule.get("name", ""))
            if not normalized_name:
                continue

            category = str(raw_rule.get("category", DEFAULT_RULE_CATEGORY)).strip() or DEFAULT_RULE_CATEGORY
            severity = str(raw_rule.get("severity", DEFAULT_RULE_SEVERITY)).strip().lower() or DEFAULT_RULE_SEVERITY
            arg_filter = str(raw_rule.get("arg_filter", DEFAULT_ARG_FILTER)).strip().lower() or DEFAULT_ARG_FILTER
            if severity not in SEVERITY_RANK:
                severity = DEFAULT_RULE_SEVERITY
            if arg_filter not in ARG_FILTER_LABELS:
                arg_filter = DEFAULT_ARG_FILTER

            normalized_rules[normalized_name] = {
                "category": category,
                "severity": severity,
                "arg_filter": arg_filter,
            }

        self.rules = normalized_rules

    def export_rules(self):
        return {
            name: {
                "category": rule["category"],
                "severity": rule["severity"],
                "arg_filter": rule.get("arg_filter", DEFAULT_ARG_FILTER),
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
            "arg_filter": rule.get("arg_filter", DEFAULT_ARG_FILTER),
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
                    "arg_filter": target.get("arg_filter", DEFAULT_ARG_FILTER),
                    "source": target["source"],
                    "line_markers": self.rule_manager.build_line_markers(
                        target["original_name"], target["normalized_name"]
                    ),
                    "summary": self._build_call_summary(xref.frm, target),
                }

                if not self._passes_argument_filter(call_info):
                    continue

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
                        "arg_filter": match.get("arg_filter", DEFAULT_ARG_FILTER),
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
                    "arg_filter": match.get("arg_filter", DEFAULT_ARG_FILTER),
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
                    "arg_filter": target.get("arg_filter", DEFAULT_ARG_FILTER),
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

    def _passes_argument_filter(self, call_info):
        arg_filter = call_info.get("arg_filter", DEFAULT_ARG_FILTER)
        if arg_filter == "any":
            return True
        if arg_filter == "non_string_args":
            return self._has_non_string_arguments(call_info["caller_func_ea"], call_info["callsite_ea"])
        if arg_filter == "first_arg_non_string":
            return self._first_argument_is_non_string(call_info["caller_func_ea"], call_info["callsite_ea"])
        if arg_filter == "has_variable_arg":
            return self._has_variable_or_pointer_argument(call_info["caller_func_ea"], call_info["callsite_ea"])
        return True

    def _has_non_string_arguments(self, func_ea, callsite_ea):
        cfunc, args = self._get_call_arguments(func_ea, callsite_ea)
        if args is None:
            return False
        if len(args) == 0:
            return False

        for arg in args:
            if not self._expr_is_string_literal(arg, cfunc):
                return True

        return False

    def _first_argument_is_non_string(self, func_ea, callsite_ea):
        cfunc, args = self._get_call_arguments(func_ea, callsite_ea)
        if args is None:
            return False
        if len(args) == 0:
            return False
        return not self._expr_is_string_literal(args[0], cfunc)

    def _has_variable_or_pointer_argument(self, func_ea, callsite_ea):
        _cfunc, args = self._get_call_arguments(func_ea, callsite_ea)
        if args is None:
            return False
        if len(args) == 0:
            return False

        for arg in args:
            if self._expr_is_variable_like(arg):
                return True

        return False

    def _get_call_arguments(self, func_ea, callsite_ea):
        try:
            cfunc = ida_hexrays.decompile(func_ea)
        except Exception:
            return None, None

        if cfunc is None:
            return None, None

        visitor = _CallArgumentFilterVisitor(callsite_ea)
        try:
            visitor.apply_to_exprs(cfunc.body, None)
        except Exception:
            return None, None

        if visitor.matched_call is None:
            return cfunc, None

        args = visitor.matched_call.a
        if args is None:
            return cfunc, []
        return cfunc, list(args)

    def _expr_is_string_literal(self, expr, cfunc=None):
        current = self._unwrap_expr(expr)

        if current is None:
            return False

        if current.op == ida_hexrays.cot_str:
            return True

        exflags = getattr(current, "exflags", 0)
        if exflags & getattr(ida_hexrays, "EXFL_CSTR", 0):
            return True

        if current.op == ida_hexrays.cot_obj:
            obj_ea = getattr(current, "obj_ea", idaapi.BADADDR)
            return self._ea_contains_string_literal(obj_ea)

        if current.op == ida_hexrays.cot_num:
            try:
                if current.maybe_ptr():
                    return self._ea_contains_string_literal(int(current.numval()))
            except Exception:
                pass

        if hasattr(current, "is_cstr") and current.is_cstr():
            return True

        rendered = self._render_expr(current, cfunc)
        return self._looks_like_rendered_string(rendered)

    def _ea_contains_string_literal(self, ea):
        if ea in (None, idaapi.BADADDR):
            return False

        try:
            if not ida_bytes.is_mapped(ea):
                return False
        except Exception:
            return False

        try:
            if ida_bytes.is_strlit_ea(ea):
                return True
        except Exception:
            pass

        str_types = []
        try:
            str_type = ida_nalt.get_str_type(ea)
        except Exception:
            str_type = None
        if str_type is not None and str_type >= 0:
            str_types.append(str_type)

        for fallback_type in (
            getattr(ida_nalt, "STRTYPE_C", None),
            getattr(ida_nalt, "STRTYPE_C_16", None),
            getattr(ida_nalt, "STRTYPE_C_32", None),
        ):
            if fallback_type is None or fallback_type in str_types:
                continue
            str_types.append(fallback_type)

        for str_type in str_types:
            try:
                content = ida_bytes.get_strlit_contents(ea, -1, str_type)
            except Exception:
                content = None
            if content:
                return True

        return False

    def _expr_is_variable_like(self, expr):
        current = self._unwrap_expr(expr)

        if current is None:
            return False

        if current.op in (
            ida_hexrays.cot_var,
            ida_hexrays.cot_ptr,
            ida_hexrays.cot_memptr,
            ida_hexrays.cot_memref,
        ):
            return True

        return False

    def _unwrap_expr(self, expr):
        current = expr
        while current is not None and current.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref):
            current = current.x
        return current

    def _render_expr(self, expr, cfunc):
        if expr is None or cfunc is None:
            return ""

        try:
            return ida_lines.tag_remove(expr.print1(cfunc)).strip()
        except Exception:
            return ""

    def _looks_like_rendered_string(self, rendered):
        if not rendered:
            return False

        text = rendered.strip()
        if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
            return True
        if text.startswith("L\"") and text.endswith('"'):
            return True
        return False


class _CallArgumentFilterVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, callsite_ea):
        super().__init__(ida_hexrays.CV_FAST)
        self.callsite_ea = callsite_ea
        self.matched_call = None

    def visit_expr(self, expr):
        if expr.op == ida_hexrays.cot_call and expr.ea == self.callsite_ea:
            self.matched_call = expr
            return 1
        return 0


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
        self.ignored_callsites = set()
        self._pending_pseudocode_refresh_funcs = set()
        self._refresh_timer = None
        self.chooser = None
        self.rule_chooser = None
        self.ignored_call_chooser = None
        self._load_rules_from_idb()
        self._load_ignored_calls_from_idb()

    def rescan(self):
        previous_funcs = set(self.calls_by_func.keys())
        self._clear_plugin_breakpoints()
        self.targets, calls, calls_by_func = self.scanner.collect()
        self.calls, self.calls_by_func = self._filter_ignored_calls(calls, calls_by_func)
        self.function_rows = self._build_function_rows()
        self._pending_pseudocode_refresh_funcs = previous_funcs | set(self.calls_by_func.keys())
        self._apply_plugin_breakpoints()
        self._log_summary()

    def clear_scan_results(self):
        previous_funcs = set(self.calls_by_func.keys())
        self._clear_plugin_breakpoints()
        self.targets = []
        self.calls = []
        self.calls_by_func = {}
        self.function_rows = []
        self._pending_pseudocode_refresh_funcs = previous_funcs

    def refresh_after_rule_change(self):
        if not self.enabled:
            return

        try:
            if self.has_rules():
                self.rescan()
            else:
                self.clear_scan_results()
                self._log_summary()

            self.refresh_current_pseudocode()
            self._schedule_chooser_refresh()
        except Exception as exc:
            log(f"automatic rescan failed: {exc}")

    def has_rules(self):
        return bool(self.rule_manager.rules)

    def show_rule_manager(self):
        if self.rule_chooser is None:
            self.rule_chooser = DangerRuleChooser(self)
        return self.rule_chooser.Show()

    def prompt_rule(
        self,
        initial_name="",
        initial_category=DEFAULT_RULE_CATEGORY,
        initial_severity=DEFAULT_RULE_SEVERITY,
        initial_arg_filter=DEFAULT_ARG_FILTER,
    ):
        return RuleEditorForm.ask(
            initial_name,
            initial_category,
            initial_severity,
            initial_arg_filter,
            self.rule_manager,
        )

    def add_or_update_rule(
        self,
        name,
        category,
        severity,
        previous_name=None,
        arg_filter=DEFAULT_ARG_FILTER,
    ):
        normalized_name = self.rule_manager.normalize_name(name)
        if not normalized_name:
            ida_kernwin.warning("Function name is empty")
            return False

        if severity not in SEVERITY_RANK:
            ida_kernwin.warning("Invalid severity")
            return False
        if arg_filter not in ARG_FILTER_LABELS:
            ida_kernwin.warning("Invalid argument filter")
            return False

        rules = self.rule_manager.export_rules()
        if previous_name:
            previous_normalized = self.rule_manager.normalize_name(previous_name)
            if previous_normalized and previous_normalized != normalized_name:
                rules.pop(previous_normalized, None)

        rules[normalized_name] = {
            "category": category or DEFAULT_RULE_CATEGORY,
            "severity": severity,
            "arg_filter": arg_filter,
        }
        self.rule_manager.import_rules(rules)
        self._save_rules_to_idb()
        self.refresh_after_rule_change()
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
        self.refresh_after_rule_change()
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
                    "arg_filter": rule.get("arg_filter", DEFAULT_ARG_FILTER),
                    "arg_filter_label": ARG_FILTER_LABELS.get(
                        rule.get("arg_filter", DEFAULT_ARG_FILTER),
                        rule.get("arg_filter", DEFAULT_ARG_FILTER),
                    ),
                }
            )
        return rows

    def ignore_callsite(self, callsite_ea):
        if callsite_ea in (None, idaapi.BADADDR):
            return False

        if callsite_ea in self.ignored_callsites:
            return False

        self.ignored_callsites.add(int(callsite_ea))
        self._save_ignored_calls_to_idb()
        self.refresh_after_rule_change()
        log(f"ignored dangerous callsite: 0x{int(callsite_ea):X}")
        return True

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

    def get_ignored_call_rows(self):
        rows = []
        for ea in sorted(self.ignored_callsites):
            caller = ida_funcs.get_func(ea)
            caller_name = ida_name.get_name(caller.start_ea) if caller is not None else ""
            if not caller_name and caller is not None:
                caller_name = f"sub_{caller.start_ea:X}"
            rows.append(
                {
                    "callsite_ea": ea,
                    "caller_func_name": caller_name or "<unknown>",
                    "summary": self.scanner._get_disasm_summary(ea),
                }
            )
        return rows

    def show_ignored_call_manager(self):
        if self.ignored_call_chooser is None:
            self.ignored_call_chooser = IgnoredCallChooser(self)
        return self.ignored_call_chooser.Show()

    def restore_ignored_callsite(self, callsite_ea):
        if callsite_ea not in self.ignored_callsites:
            return False

        self.ignored_callsites.discard(int(callsite_ea))
        self._save_ignored_calls_to_idb()
        self.refresh_after_rule_change()
        log(f"restored dangerous callsite: 0x{int(callsite_ea):X}")
        return True

    def refresh_current_pseudocode(self):
        refreshed = False

        open_funcs = set(self._pending_pseudocode_refresh_funcs) | {call["caller_func_ea"] for call in self.calls}
        current_widget = ida_kernwin.get_current_widget()
        if current_widget is not None and ida_kernwin.get_widget_type(current_widget) == ida_kernwin.BWN_PSEUDOCODE:
            current_vu = ida_hexrays.get_widget_vdui(current_widget)
            if current_vu is not None:
                try:
                    current_vu.refresh_view(True)
                    refreshed = True
                except Exception:
                    pass

        for func_ea in sorted(open_funcs):
            try:
                vu = ida_hexrays.open_pseudocode(func_ea, ida_hexrays.OPF_REUSE)
            except Exception:
                vu = None
            if vu is None:
                continue
            try:
                vu.refresh_view(True)
                refreshed = True
            except Exception:
                continue

        self._pending_pseudocode_refresh_funcs = set()

        if not refreshed:
            try:
                ida_kernwin.mark_builtin_widget_by_id(ida_kernwin.BWN_PSEUDOCODE, True)
            except Exception:
                ida_kernwin.refresh_idaview_anyway()

    def disable(self, shutting_down=False):
        self.enabled = False
        self.clear_scan_results()
        self.close_choosers()
        if not shutting_down:
            self.refresh_current_pseudocode()
        log("plugin disabled")

    def enable(self):
        self.enabled = True
        self.refresh_current_pseudocode()
        log("plugin enabled")

    def close_choosers(self):
        self._cancel_scheduled_refresh()

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

        if self.ignored_call_chooser is not None:
            try:
                self.ignored_call_chooser.Close()
            except Exception:
                pass

    def _refresh_open_choosers(self):
        self._refresh_rule_chooser()
        self._reopen_call_chooser()
        self._reopen_ignored_call_chooser()

    def _refresh_rule_chooser(self):
        if self.rule_chooser is None:
            return

        try:
            force_refresh = getattr(self.rule_chooser, "force_refresh", None)
            if callable(force_refresh):
                force_refresh()
            else:
                self.rule_chooser.Refresh()
        except Exception:
            pass

    def _reopen_call_chooser(self):
        if self.chooser is None:
            return

        try:
            self.chooser.Close()
        except Exception:
            pass

        self.chooser = DangerCallChooser(self)
        try:
            self.chooser.Show()
        except Exception:
            pass

    def _reopen_ignored_call_chooser(self):
        if self.ignored_call_chooser is None:
            return

        try:
            self.ignored_call_chooser.Close()
        except Exception:
            pass

        self.ignored_call_chooser = IgnoredCallChooser(self)
        try:
            self.ignored_call_chooser.Show()
        except Exception:
            pass

    def _schedule_chooser_refresh(self):
        if self._refresh_timer is not None:
            return

        def _run_refresh():
            self._refresh_timer = None
            self._refresh_open_choosers()
            return -1

        try:
            self._refresh_timer = ida_kernwin.register_timer(0, _run_refresh)
        except Exception:
            self._refresh_open_choosers()

    def _cancel_scheduled_refresh(self):
        if self._refresh_timer is None:
            return

        try:
            ida_kernwin.unregister_timer(self._refresh_timer)
        except Exception:
            pass
        self._refresh_timer = None

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

    def _filter_ignored_calls(self, calls, calls_by_func):
        if not self.ignored_callsites:
            return calls, calls_by_func

        filtered_calls = []
        filtered_calls_by_func = {}

        for call in calls:
            if call["callsite_ea"] in self.ignored_callsites:
                continue
            filtered_calls.append(call)
            filtered_calls_by_func.setdefault(call["caller_func_ea"], []).append(call)

        return filtered_calls, filtered_calls_by_func

    def _get_rules_node(self, create=False):
        if create:
            return ida_netnode.netnode(RULES_NODE_NAME, 0, True)
        return ida_netnode.netnode(RULES_NODE_NAME)

    def _get_ignored_calls_node(self, create=False):
        if create:
            return ida_netnode.netnode(IGNORED_CALLS_NODE_NAME, 0, True)
        return ida_netnode.netnode(IGNORED_CALLS_NODE_NAME)

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

    def _load_ignored_calls_from_idb(self):
        try:
            node = self._get_ignored_calls_node(create=False)
            data = node.getblob(IGNORED_CALLS_BLOB_INDEX, IGNORED_CALLS_BLOB_TAG)
        except Exception:
            data = None

        if not data:
            self.ignored_callsites = set()
            return

        try:
            raw_callsites = json.loads(data.decode("utf-8"))
        except Exception as exc:
            log(f"failed to load ignored callsites from IDB: {exc}")
            self.ignored_callsites = set()
            return

        if not isinstance(raw_callsites, list):
            self.ignored_callsites = set()
            return

        ignored = set()
        for item in raw_callsites:
            try:
                ignored.add(int(item))
            except Exception:
                continue
        self.ignored_callsites = ignored

    def _save_rules_to_idb(self):
        try:
            node = self._get_rules_node(create=True)
            payload = json.dumps(self.rule_manager.export_rules(), sort_keys=True).encode("utf-8")
            node.setblob(payload, RULES_BLOB_INDEX, RULES_BLOB_TAG)
        except Exception as exc:
            log(f"failed to save dangerous function list to IDB: {exc}")

    def _save_ignored_calls_to_idb(self):
        try:
            node = self._get_ignored_calls_node(create=True)
            payload = json.dumps(sorted(self.ignored_callsites)).encode("utf-8")
            node.setblob(payload, IGNORED_CALLS_BLOB_INDEX, IGNORED_CALLS_BLOB_TAG)
        except Exception as exc:
            log(f"failed to save ignored callsites to IDB: {exc}")


class DangerCallChooser(ida_kernwin.Choose):
    """
    Non-modal result panel for browsing dangerous callsites.
    """

    def __init__(self, state):
        self.state = state
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
            flags=(
                ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_REFRESH
                | ida_kernwin.Choose.CH_CAN_DEL
            ),
            embedded=False,
        )

    def _rows(self):
        return self.state.get_all_calls()

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
        call = self._rows()[n]
        return [
            f"0x{call['callsite_ea']:X}",
            call["caller_func_name"],
            call["callee_normalized_name"],
            call["risk_category"],
            call["severity"],
            call["source"],
            call.get("summary", ""),
        ]

    def OnRefresh(self, n):
        return n

    def OnSelectLine(self, n):
        calls = self._rows()
        if n < 0 or n >= len(calls):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        call = calls[n]
        self._jump_to_call(call)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnDeleteLine(self, sel):
        calls = self._rows()
        if sel < 0 or sel >= len(calls):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        call = calls[sel]
        if not self.state.ignore_callsite(call["callsite_ea"]):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(sel)

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


class IgnoredCallChooser(ida_kernwin.Choose):
    def __init__(self, state):
        self.state = state
        columns = [
            ["Callsite", 12],
            ["Caller", 28],
            ["Summary", 56],
        ]
        super().__init__(
            "Locatespace Ignored Calls",
            columns,
            flags=(
                ida_kernwin.Choose.CH_RESTORE
                | ida_kernwin.Choose.CH_CAN_DEL
                | ida_kernwin.Choose.CH_CAN_REFRESH
            ),
            embedded=False,
        )

    def _rows(self):
        return self.state.get_ignored_call_rows()

    def force_refresh(self):
        try:
            self.Refresh()
        except Exception:
            pass

    def OnGetSize(self):
        return len(self._rows())

    def OnGetLine(self, n):
        row = self._rows()[n]
        return [
            f"0x{row['callsite_ea']:X}",
            row["caller_func_name"],
            row["summary"],
        ]

    def OnRefresh(self, n):
        return n

    def OnSelectLine(self, n):
        rows = self._rows()
        if n < 0 or n >= len(rows):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)
        ida_kernwin.jumpto(rows[n]["callsite_ea"])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnDeleteLine(self, sel):
        rows = self._rows()
        if sel < 0 or sel >= len(rows):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        row = rows[sel]
        if not self.state.restore_ignored_callsite(row["callsite_ea"]):
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        return [ida_kernwin.Choose.ALL_CHANGED] + self.adjust_last_item(sel)


class RuleEditorForm(ida_kernwin.Form):
    SEVERITY_OPTIONS = ["critical", "high", "medium", "low"]
    ARG_FILTER_OPTIONS = [
        ("any", "Any arguments"),
        ("non_string_args", "Require non-string arguments"),
        ("first_arg_non_string", "First arg non-string"),
        ("has_variable_arg", "Any variable/pointer arg"),
    ]
    CATEGORY_OPTIONS = [
        "custom",
        "buffer_write",
        "format_string",
        "command_exec",
        "memory_copy",
    ]

    def __init__(self, name, category, severity, arg_filter):
        F = ida_kernwin.Form
        category_options = list(self.CATEGORY_OPTIONS)
        if category and category not in category_options:
            category_options.append(category)

        severity_options = list(self.SEVERITY_OPTIONS)
        if severity and severity not in severity_options:
            severity_options.append(severity)
        severity_index = severity_options.index(severity if severity in severity_options else DEFAULT_RULE_SEVERITY)
        arg_filter_values = [item[0] for item in self.ARG_FILTER_OPTIONS]
        arg_filter_labels = [item[1] for item in self.ARG_FILTER_OPTIONS]
        arg_filter_index = arg_filter_values.index(arg_filter if arg_filter in arg_filter_values else DEFAULT_ARG_FILTER)

        F.__init__(
            self,
            r"""
BUTTON YES* Save
BUTTON CANCEL Cancel
Locatespace rule

<Function name:{name}>
<Category:{category}>
<Severity:{severity}>
<Argument filter:{arg_filter}>
""",
            {
                "name": F.StringInput(swidth=40),
                "category": F.DropdownListControl(items=category_options, readonly=False, selval=category),
                "severity": F.DropdownListControl(items=severity_options, readonly=True, selval=severity_index),
                "arg_filter": F.DropdownListControl(items=arg_filter_labels, readonly=True, selval=arg_filter_index),
            },
        )
        self._severity_options = severity_options
        self._arg_filter_values = arg_filter_values

    @classmethod
    def ask(cls, name, category, severity, arg_filter, rule_manager):
        normalized_name = rule_manager.normalize_name(name) if name else ""
        initial_name = normalized_name or name
        initial_category = category or DEFAULT_RULE_CATEGORY
        initial_severity = severity or DEFAULT_RULE_SEVERITY
        initial_arg_filter = arg_filter or DEFAULT_ARG_FILTER

        form = cls(initial_name, initial_category, initial_severity, initial_arg_filter)
        form, _args = form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return None

        selected_name = (form.name.value or "").strip()
        selected_category = (form.category.value or "").strip()
        severity_index = form.severity.value
        if not isinstance(severity_index, int) or severity_index < 0 or severity_index >= len(form._severity_options):
            if initial_severity in form._severity_options:
                severity_index = form._severity_options.index(initial_severity)
            else:
                severity_index = form._severity_options.index(DEFAULT_RULE_SEVERITY)
        selected_severity = form._severity_options[severity_index]
        arg_filter_index = form.arg_filter.value
        if not isinstance(arg_filter_index, int) or arg_filter_index < 0 or arg_filter_index >= len(form._arg_filter_values):
            arg_filter_index = form._arg_filter_values.index(initial_arg_filter)
        selected_arg_filter = form._arg_filter_values[arg_filter_index]
        form.Free()

        if not selected_name:
            ida_kernwin.warning("Function name is empty")
            return None

        return {
            "name": selected_name,
            "category": selected_category or DEFAULT_RULE_CATEGORY,
            "severity": selected_severity,
            "arg_filter": selected_arg_filter,
        }


class DangerRuleChooser(ida_kernwin.Choose):
    def __init__(self, state):
        self.state = state
        columns = [
            ["Function", 24],
            ["Category", 18],
            ["Severity", 10],
            ["Arg Filter", 24],
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
        return [
            row["name"],
            row["category"],
            row["severity"],
            row.get("arg_filter_label", row.get("arg_filter", DEFAULT_ARG_FILTER)),
        ]

    def OnRefresh(self, n):
        return None

    def OnInsertLine(self, sel):
        rule = self.state.prompt_rule()
        if rule is None:
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        if not self.state.add_or_update_rule(
            rule["name"],
            rule["category"],
            rule["severity"],
            arg_filter=rule.get("arg_filter", DEFAULT_ARG_FILTER),
        ):
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
        current_arg_filter = current_row.get("arg_filter", DEFAULT_ARG_FILTER)
        rule = self.state.prompt_rule(current_name, current_category, current_severity, current_arg_filter)
        if rule is None:
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

        if not self.state.add_or_update_rule(
            rule["name"],
            rule["category"],
            rule["severity"],
            previous_name=current_name,
            arg_filter=rule.get("arg_filter", DEFAULT_ARG_FILTER),
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

        rendered_call_texts = self._build_rendered_call_texts(cfunc, calls)
        highlighted_lines = self._highlight_by_address(cfunc, pseudocode, calls)
        for line in pseudocode:
            if line in highlighted_lines:
                continue
            plain_line = ida_lines.tag_remove(line.line)
            best_call = self._find_best_call_for_line(plain_line, calls, rendered_call_texts)
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

    def _find_best_call_for_line(self, plain_line, calls, rendered_call_texts):
        """
        Choose the highest-severity dangerous call whose rendered call text
        appears in this line.

        This is stricter than matching only by callee name and avoids false
        positives when a function contains multiple calls to the same sink with
        different arguments.
        """

        normalized_line = self._normalize_match_text(plain_line)
        if not normalized_line:
            return None

        best_call = None
        best_rank = 0

        for call in calls:
            rendered_call = rendered_call_texts.get(call["callsite_ea"], "")
            if not rendered_call or rendered_call not in normalized_line:
                continue

            rank = SEVERITY_RANK.get(call["severity"], 0)
            if rank > best_rank:
                best_rank = rank
                best_call = call

        return best_call

    def _build_rendered_call_texts(self, cfunc, calls):
        rendered = {}
        for call in calls:
            text = self._render_callsite_text(cfunc, call["callsite_ea"])
            if not text:
                continue
            rendered[call["callsite_ea"]] = text
        return rendered

    def _render_callsite_text(self, cfunc, callsite_ea):
        visitor = _CallArgumentFilterVisitor(callsite_ea)
        try:
            visitor.apply_to_exprs(cfunc.body, None)
        except Exception:
            return ""

        if visitor.matched_call is None:
            return ""

        try:
            rendered = ida_lines.tag_remove(visitor.matched_call.print1(cfunc)).strip()
        except Exception:
            return ""

        return self._normalize_match_text(rendered)

    def _normalize_match_text(self, text):
        if not text:
            return ""
        return re.sub(r"\s+", " ", text).strip()

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

    def manage_ignored_calls(self):
        if self.state is None:
            log("plugin state is not ready")
            return
        if not self.state.enabled:
            log("plugin is disabled")
            return

        self.state.show_ignored_call_manager()

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
                self.state.disable(shutting_down=True)
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
            ACTION_MANAGE_IGNORED,
            "Locatespace: Manage ignored callsites",
            self.manage_ignored_calls,
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
        for name in (ACTION_SCAN, ACTION_EDIT_RULES, ACTION_MANAGE_IGNORED, ACTION_DISABLE, ACTION_ENABLE):
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
