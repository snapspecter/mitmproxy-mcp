import re
import logging
from typing import Dict
from mitmproxy import http
from ..models import InterceptionRule
from .utils import get_safe_text

logger = logging.getLogger("mcp_mitm")


class TrafficInterceptor:
    """Applies dynamic rules to modify traffic on the fly."""

    def __init__(self):
        self.rules: Dict[str, InterceptionRule] = {}
        self._compiled_patterns: Dict[str, Dict[str, re.Pattern]] = {}

    def add_rule(self, rule: InterceptionRule):
        self.rules[rule.id] = rule

        # Pre-compile regex patterns
        patterns = {}
        try:
            if rule.url_pattern:
                patterns["url"] = re.compile(rule.url_pattern)
            if rule.search_pattern:
                patterns["search"] = re.compile(rule.search_pattern)
        except re.error as e:
            logger.warning("Failed to compile regex for rule %s: %s", rule.id, e)

        self._compiled_patterns[rule.id] = patterns
        logger.info("Added interception rule: %s", rule)

    def remove_rule(self, rule_id: str):
        if rule_id in self.rules:
            del self.rules[rule_id]
        if rule_id in self._compiled_patterns:
            del self._compiled_patterns[rule_id]

    def clear_rules(self):
        self.rules.clear()
        self._compiled_patterns.clear()

    def get_active_rules(self):
        return list(self.rules.values())

    def request(self, flow: http.HTTPFlow):
        self._apply_rules(flow, "request")

    def response(self, flow: http.HTTPFlow):
        self._apply_rules(flow, "response")

    def _apply_rules(self, flow: http.HTTPFlow, phase: str):
        message = getattr(flow, phase)
        if not message:
            return

        for rule in self.rules.values():
            if not rule.active or rule.resource_type != phase:
                continue

            if rule.method and flow.request.method != rule.method:
                continue

            compiled = self._compiled_patterns.get(rule.id, {})
            url_pattern = compiled.get("url")

            if url_pattern:
                if not url_pattern.search(flow.request.url):
                    continue
            elif rule.url_pattern:
                if not re.search(rule.url_pattern, flow.request.url):
                    continue

            try:
                if (
                    rule.action_type == "inject_header"
                    and rule.key
                    and rule.value
                ):
                    message.headers[rule.key] = rule.value
                    logger.info(
                        "Injected header: '%s' using: '%s'",
                        rule.key,
                        rule.id,
                    )

                elif (
                    rule.action_type == "replace_body"
                    and rule.search_pattern
                    and rule.value
                ):
                    text = get_safe_text(message)
                    if text is not None:
                        search_pattern = compiled.get("search")
                        if search_pattern:
                            new_text = search_pattern.sub(rule.value, text)
                        else:
                            new_text = re.sub(
                                rule.search_pattern,
                                rule.value,
                                text,
                            )
                        message.text = new_text
                        logger.info(
                            "Body modified by rule: '%s'",
                            rule.id,
                        )

                elif rule.action_type == "block":
                    flow.kill()
                    logger.info(
                        "Request blocked per rule: '%s'",
                        rule.id,
                    )

            except Exception as e:
                logger.error(
                    "[ERROR] Couldn't apply rule:  '%s': %s",
                    rule.id,
                    e,
                )
