from burp import IBurpExtender, IHttpListener, ITab, IContextMenuFactory

from java.awt import BorderLayout, Color, FlowLayout
from java.lang import Object, Runnable, Thread
from java.net import URL
from javax.swing import (
    JButton,
    JCheckBox,
    JLabel,
    JMenuItem,
    JOptionPane,
    JPanel,
    JScrollPane,
    JSplitPane,
    JTable,
    JTextArea,
    JTextField,
    SwingUtilities,
)
from javax.swing.table import DefaultTableCellRenderer, DefaultTableModel

from threading import Lock
import re
import socket
import time


class BurpExtender(IBurpExtender, IHttpListener, ITab, IContextMenuFactory):
    MAX_SAMPLES_PER_HOST = 5
    MAX_CONCURRENT_EVAL = 5
    LIKELY_RESULTS = ["CONFIRMED_ORIGIN", "LIKELY_ORIGIN", "POSSIBLE_ORIGIN"]
    PUBLIC_SUFFIX_2L = set([
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "co.in", "org.in", "net.in", "gov.in",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "net.br", "org.br",
    ])
    NOISE_SUFFIXES = [
        ".google.com",
        ".googleapis.com",
        ".gstatic.com",
        ".doubleclick.net",
        ".googletagmanager.com",
        ".google-analytics.com",
        ".googlesyndication.com",
        ".facebook.com",
        ".facebook.net",
        ".fbcdn.net",
        ".cloudfront.net",
        ".akamaihd.net",
        ".akamaized.net",
        ".jsdelivr.net",
        ".bootstrapcdn.com",
        ".fontawesome.com",
        ".cloudflare.com",
        ".cloudflareinsights.com",
        ".sentry.io",
        ".segment.io",
        ".hotjar.com",
    ]
    LOW_SIGNAL_SUFFIXES = [
        ".google.com",
        ".google.co.in",
        ".google.co.uk",
        ".linkedin.com",
        ".g2.com",
        ".piwik.pro",
        ".stackadapt.com",
    ]

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self._callbacks.setExtensionName("OriginIpAutoDetect Beta")
        self._callbacks.registerHttpListener(self)
        self._callbacks.registerContextMenuFactory(self)

        self._host_samples = {}
        self._host_rows = {}
        self._visible_rows = {}
        self._evaluating_hosts = set()
        self._pending_hosts = []
        self._active_evals = 0
        self._history_import_started = False
        self._state_lock = Lock()
        self._stats = self._fresh_stats()

        self._build_ui()
        self._callbacks.addSuiteTab(self)

        self._run_in_background("origin-auto-history-beta", self._HistoryImporter(self))
        self._log("Extension loaded")

    def getTabCaption(self):
        return "OriginIpAutoDetect Beta"

    def getUiComponent(self):
        return self._ui

    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None

        menu_items = java_array_list()
        menu_items.add(
            JMenuItem(
                "Send to OriginIpAutoDetect Beta",
                actionPerformed=lambda event: self._import_messages(messages, "selection"),
            )
        )
        return menu_items

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        if toolFlag != self._callbacks.TOOL_PROXY:
            return

        self._run_in_background(
            "origin-live-response-beta",
            self._MessageProcessor(self, messageInfo, False, "live"),
        )

    def _build_ui(self):
        columns = [
            "Host",
            "Base Domain",
            "Scheme",
            "Port",
            "Candidate IPs",
            "Origin IP",
            "Result",
            "Score",
            "Matches",
            "Probe Status",
            "Probe Length",
            "Sources",
            "Notes",
        ]

        self._table_model = DefaultTableModel(columns, 0)
        self._table = JTable(self._table_model)
        self._table.setDefaultRenderer(Object, ResultCellRenderer())

        self._log_area = JTextArea()
        self._log_area.setEditable(False)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self._scope_only_checkbox = JCheckBox(
            "Only In Scope", False, actionPerformed=self._on_filter_changed
        )
        self._likely_only_checkbox = JCheckBox(
            "Only Likely Origin", False, actionPerformed=self._refresh_table
        )
        self._suppress_low_signal_checkbox = JCheckBox(
            "Suppress Low Signal", True, actionPerformed=self._refresh_table
        )
        self._active_probe_checkbox = JCheckBox(
            "Enable Active Probing", True, actionPerformed=self._on_filter_changed
        )
        self._site_map_targets = JTextField(30)

        load_history_button = JButton(
            "Import HTTP History",
            actionPerformed=lambda event: self._run_in_background(
                "origin-manual-history-beta",
                self._HistoryImporter(self, force=True, reset_run_stats=True),
            ),
        )
        load_site_map_button = JButton(
            "Import Site Map Targets",
            actionPerformed=lambda event: self._import_site_map_targets(),
        )
        clear_button = JButton("Clear", actionPerformed=lambda event: self._clear_state())

        controls.add(self._scope_only_checkbox)
        controls.add(self._likely_only_checkbox)
        controls.add(self._suppress_low_signal_checkbox)
        controls.add(self._active_probe_checkbox)
        controls.add(JLabel("Site map prefixes:"))
        controls.add(self._site_map_targets)
        controls.add(load_history_button)
        controls.add(load_site_map_button)
        controls.add(clear_button)

        split = JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            JScrollPane(self._table),
            JScrollPane(self._log_area),
        )
        split.setResizeWeight(0.72)

        panel = JPanel(BorderLayout())
        panel.add(controls, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)

        self._ui = panel
        self._callbacks.customizeUiComponent(self._ui)

    def _fresh_stats(self):
        return {
            "seen": 0,
            "added": 0,
            "skipped_ip": 0,
            "skipped_scope": 0,
            "skipped_noise": 0,
            "skipped_duplicate": 0,
            "hosts_evaluated": 0,
        }

    def _import_site_map_targets(self):
        raw_targets = self._site_map_targets.getText().strip()
        prefixes = [item.strip() for item in raw_targets.split(",") if item.strip()]
        if not prefixes:
            JOptionPane.showMessageDialog(
                self._ui,
                "Enter one or more site map prefixes, separated by commas.",
                "OriginIpAutoDetect Beta",
                JOptionPane.INFORMATION_MESSAGE,
            )
            return

        total = 0
        for prefix in prefixes:
            try:
                items = self._callbacks.getSiteMap(prefix)
            except Exception as exc:
                self._log("Failed to read Site Map for %s: %s" % (prefix, exc))
                continue

            total += len(items)
            self._log("Site Map items for %s: %d" % (prefix, len(items)))
            self._import_messages(items, "site-map")

        self._log("Imported Site Map messages: %d" % total)

    def _import_proxy_history(self, force=False, reset_run_stats=False):
        with self._state_lock:
            if self._history_import_started and not force:
                return
            if not self._history_import_started:
                self._history_import_started = True
            if reset_run_stats:
                self._stats = self._fresh_stats()

        self._log("Importing Burp proxy history")

        try:
            history = self._callbacks.getProxyHistory()
        except Exception as exc:
            self._log("Failed to read proxy history: %s" % exc)
            return

        self._log("Proxy history entries: %d" % len(history))
        self._import_messages(history, "http-history", from_history=True)
        self._log(
            "History summary: seen=%d added=%d evaluated=%d skipped_ip=%d skipped_scope=%d skipped_noise=%d skipped_duplicate=%d"
            % (
                self._stats["seen"],
                self._stats["added"],
                self._stats["hosts_evaluated"],
                self._stats["skipped_ip"],
                self._stats["skipped_scope"],
                self._stats["skipped_noise"],
                self._stats["skipped_duplicate"],
            )
        )
        self._log("Proxy history import complete")

    def _import_messages(self, messages, source_label, from_history=False):
        added = 0
        for item in messages:
            if self._process_item(item, from_history, source_label):
                added += 1

        if not from_history:
            self._log("Imported %d messages from %s" % (added, source_label))

    def _process_item(self, item, from_history, source_label):
        try:
            if from_history:
                self._stats["seen"] += 1

            request = item.getRequest()
            response = item.getResponse()
            if not request or not response:
                return False

            request_info = self._helpers.analyzeRequest(item)
            url = request_info.getUrl()
            if not url:
                return False

            host = (url.getHost() or "").lower()
            if not host:
                return False

            if self._is_ip(host):
                if from_history:
                    self._stats["skipped_ip"] += 1
                return False

            skip_reason = self._skip_reason(url)
            if skip_reason:
                if from_history:
                    if skip_reason == "scope":
                        self._stats["skipped_scope"] += 1
                    elif skip_reason == "noise":
                        self._stats["skipped_noise"] += 1
                return False

            return self._record_sample(item, url, request, response, source_label, from_history)
        except Exception as exc:
            self._log("Failed to process %s item: %s" % (source_label, exc))
            return False

    def _record_sample(self, item, url, request, response, source_label, from_history):
        host = (url.getHost() or "").lower()
        sample_key = self._sample_key(item, url)

        with self._state_lock:
            samples = self._host_samples.get(host)
            if samples is None:
                samples = []
                self._host_samples[host] = samples

            for sample in samples:
                if sample["key"] == sample_key:
                    if from_history:
                        self._stats["skipped_duplicate"] += 1
                    return False

            if len(samples) >= self.MAX_SAMPLES_PER_HOST:
                if from_history:
                    self._stats["skipped_duplicate"] += 1
                return False

            samples.append(
                {
                    "key": sample_key,
                    "item": item,
                    "url": url,
                    "request": request,
                    "response": response,
                    "source": source_label,
                }
            )
            if from_history:
                self._stats["added"] += 1

            if host in self._evaluating_hosts:
                return True

            self._evaluating_hosts.add(host)

        self._schedule_host_evaluation(host)
        return True

    def _schedule_host_evaluation(self, host):
        should_start = False
        with self._state_lock:
            if self._active_evals < self.MAX_CONCURRENT_EVAL:
                self._active_evals += 1
                should_start = True
            elif host not in self._pending_hosts:
                self._pending_hosts.append(host)
                self._log("Queued %s for evaluation" % host)

        if should_start:
            self._run_in_background("origin-eval-beta-" + host, self._HostEvaluator(self, host))

    def _evaluate_host(self, host):
        try:
            with self._state_lock:
                samples = list(self._host_samples.get(host, []))

            if not samples:
                return

            first_url = samples[0]["url"]
            scheme = first_url.getProtocol() or "http"
            port = first_url.getPort()
            if port == -1:
                port = 443 if scheme == "https" else 80

            candidate_ips = self._resolve_candidate_ips(host)
            best = self._probe_candidates(host, samples, candidate_ips)
            best = self._post_process_verdict(host, best)

            row = [
                host,
                self._base_domain(host),
                scheme,
                port,
                ", ".join(candidate_ips) if candidate_ips else "unresolved",
                best["origin_ip"],
                best["result"],
                best["score"],
                best["matches"],
                best["probe_status"],
                best["probe_length"],
                self._source_summary(samples),
                best["notes"],
            ]

            with self._state_lock:
                self._host_rows[host] = row
                self._stats["hosts_evaluated"] += 1

            self._refresh_table(None)
            self._log(
                "Source=%s Host=%s BaseDomain=%s Port=%s Candidates=%s OriginIP=%s Result=%s Score=%s Matches=%s Status=%s Length=%s Notes=%s"
                % (
                    row[11],
                    host,
                    row[1],
                    port,
                    row[4],
                    row[5] if row[5] else "none",
                    row[6],
                    row[7],
                    row[8],
                    row[9],
                    row[10],
                    row[12] if row[12] else "none",
                )
            )
        finally:
            self._mark_host_eval_complete(host)

    def _probe_candidates(self, host, samples, candidate_ips):
        if not self._active_probe_checkbox.isSelected():
            return self._empty_verdict("PROBING_DISABLED", "disabled", 0, "Active probing disabled")

        if not candidate_ips:
            return self._empty_verdict("UNRESOLVED", "unresolved", 0, "DNS did not resolve")

        best = None
        for ip in candidate_ips:
            evaluation = self._evaluate_candidate(host, ip, samples)
            if not evaluation:
                continue

            if best is None or evaluation["score_value"] > best["score_value"]:
                best = evaluation

        if not best:
            return self._empty_verdict("NO_RESPONSE", "no-response", 0, "No probe responses")

        return best

    def _empty_verdict(self, label, probe_status, probe_length, notes):
        return {
            "origin_ip": "",
            "result": label,
            "score": "0/100",
            "score_value": 0,
            "matches": "0/0",
            "probe_status": probe_status,
            "probe_length": probe_length,
            "notes": notes,
            "blocked_ratio": 0.0,
        }

    def _evaluate_candidate(self, host, ip, samples):
        total_score = 0.0
        strong_matches = 0
        responses_seen = 0
        blocked_count = 0
        last_status = "no-response"
        last_length = 0
        weak_signal_count = 0
        best_variant_notes = ""

        for sample in samples:
            time.sleep(0.15)
            original_host = (sample["url"].getHost() or "").lower()

            ip_host_response = self._send_probe_request(
                sample["item"], sample["url"], sample["request"], ip, ip
            )
            original_host_response = self._send_probe_request(
                sample["item"], sample["url"], sample["request"], ip, original_host
            )

            variant_results = []
            if ip_host_response:
                result_ip = self._compare_response_pair(sample["url"], sample["response"], ip_host_response)
                result_ip["variant"] = "host=ip"
                variant_results.append(result_ip)

            if original_host_response:
                result_host = self._compare_response_pair(sample["url"], sample["response"], original_host_response)
                result_host["variant"] = "host=domain"
                variant_results.append(result_host)

            if not variant_results:
                continue

            best_variant = max(variant_results, key=lambda item: item["score"])
            responses_seen += 1
            total_score += best_variant["score"]
            last_status = best_variant["status"]
            last_length = best_variant["length"]
            best_variant_notes = best_variant["variant"]

            if best_variant["blocked"]:
                blocked_count += 1
            if best_variant["weak_signal"]:
                weak_signal_count += 1
            if best_variant["score"] >= 75:
                strong_matches += 1

        if responses_seen == 0:
            return None

        average_score = int(total_score / float(responses_seen))
        return {
            "origin_ip": ip,
            "result": self._classify_candidate_score(
                average_score, strong_matches, responses_seen, blocked_count
            ),
            "score": "%d/100" % average_score,
            "score_value": average_score,
            "matches": "%d/%d" % (strong_matches, responses_seen),
            "probe_status": last_status,
            "probe_length": last_length,
            "notes": self._candidate_notes(blocked_count, responses_seen, weak_signal_count, best_variant_notes),
            "blocked_ratio": blocked_count / float(max(responses_seen, 1)),
            "weak_signal_ratio": weak_signal_count / float(max(responses_seen, 1)),
        }

    def _candidate_notes(self, blocked_count, responses_seen, weak_signal_count, variant_note):
        notes = []
        if variant_note:
            notes.append(variant_note)
        if blocked_count and responses_seen:
            notes.append("blocked=%d/%d" % (blocked_count, responses_seen))
        if weak_signal_count and responses_seen:
            notes.append("weak=%d/%d" % (weak_signal_count, responses_seen))
        return ", ".join(notes)

    def _post_process_verdict(self, host, verdict):
        notes = []
        result = verdict["result"]
        score_value = verdict["score_value"]

        if self._is_low_signal_host(host):
            notes.append("low-signal-host")
            if result == "POSSIBLE_ORIGIN":
                result = "INCONCLUSIVE"
            elif result == "LIKELY_ORIGIN" and score_value < 90:
                result = "POSSIBLE_ORIGIN"

        if verdict.get("blocked_ratio", 0.0) >= 0.5 and result in ["POSSIBLE_ORIGIN", "LIKELY_ORIGIN"]:
            result = "RESPONDS_BUT_BLOCKED"
            notes.append("Possible origin behind WAF/CDN")

        if score_value < 60 and result == "POSSIBLE_ORIGIN":
            result = "INCONCLUSIVE"
            notes.append("score-below-60")

        if verdict["notes"]:
            notes.append(verdict["notes"])

        verdict["result"] = result
        verdict["notes"] = ", ".join([note for note in notes if note])
        return verdict

    def _send_probe_request(self, item, url, request, ip, host_header):
        request_bytes = self._build_ip_request(item, url, request, host_header)
        service = item.getHttpService()
        port = service.getPort()
        protocol = service.getProtocol()

        try:
            response_wrapper = self._callbacks.makeHttpRequest(
                self._helpers.buildHttpService(ip, port, protocol),
                request_bytes,
            )
            if response_wrapper and response_wrapper.getResponse():
                return response_wrapper.getResponse()
        except Exception as exc:
            self._log("Probe error for %s via %s over %s: %s" % (url.getHost(), ip, protocol, exc))

        if str(protocol).lower() == "https":
            try:
                fallback_wrapper = self._callbacks.makeHttpRequest(
                    self._helpers.buildHttpService(ip, 80, "http"),
                    request_bytes,
                )
                if fallback_wrapper and fallback_wrapper.getResponse():
                    self._log("Fallback HTTP probe succeeded for %s via %s" % (url.getHost(), ip))
                    return fallback_wrapper.getResponse()
            except Exception as exc:
                self._log("Fallback HTTP probe failed for %s via %s: %s" % (url.getHost(), ip, exc))

        return None

    def _build_ip_request(self, item, url, request, host_header):
        request_info = self._helpers.analyzeRequest(item)
        headers = list(request_info.getHeaders())
        if not headers:
            return request

        headers[0] = self._normalize_request_line(headers[0], url)
        sanitized_headers = []
        host_set = False

        for header in headers[1:]:
            lower = header.lower()
            if lower.startswith("proxy-connection:"):
                continue
            if lower.startswith("host:"):
                sanitized_headers.append("Host: %s" % host_header)
                host_set = True
            else:
                sanitized_headers.append(header)

        if not host_set:
            sanitized_headers.append("Host: %s" % host_header)

        final_headers = [headers[0]] + sanitized_headers
        body_offset = request_info.getBodyOffset()
        body = request[body_offset:]
        return self._helpers.buildHttpMessage(final_headers, body)

    def _compare_response_pair(self, url, original_response, probe_response):
        probe_info = self._helpers.analyzeResponse(probe_response)
        probe_status = probe_info.getStatusCode()
        probe_length = len(probe_response)

        if not original_response:
            return {
                "score": 20,
                "status": str(probe_status),
                "length": probe_length,
                "blocked": False,
                "weak_signal": True,
            }

        original_info = self._helpers.analyzeResponse(original_response)
        original_status = original_info.getStatusCode()

        original_body = self._body_text(original_response, original_info)
        probe_body = self._body_text(probe_response, probe_info)

        original_title = self._extract_title(original_body)
        probe_title = self._extract_title(probe_body)
        original_server = self._get_header_value(original_info.getHeaders(), "Server")
        probe_server = self._get_header_value(probe_info.getHeaders(), "Server")
        original_type = self._get_header_value(original_info.getHeaders(), "Content-Type")
        probe_type = self._get_header_value(probe_info.getHeaders(), "Content-Type")
        original_location = self._get_header_value(original_info.getHeaders(), "Location")
        probe_location = self._get_header_value(probe_info.getHeaders(), "Location")

        status_match = original_status == probe_status
        title_match = bool(original_title) and original_title == probe_title
        server_match = bool(original_server) and original_server == probe_server
        type_match = (
            bool(original_type)
            and self._content_type_family(original_type) == self._content_type_family(probe_type)
        )
        redirect_match = self._redirects_match(original_location, probe_location, url.getHost())
        text_similarity = self._text_similarity(original_body, probe_body)
        body_delta = self._relative_length_delta(len(original_body), len(probe_body))
        blocked = self._looks_like_direct_ip_block(
            probe_status, probe_body, probe_title, probe_location
        )

        weak_signal = False
        score = 0

        if status_match:
            score += 20
        elif self._is_redirect_status(original_status) and self._is_redirect_status(probe_status):
            score += 10

        if redirect_match:
            score += 25
        if title_match:
            score += 15
        if server_match:
            score += 10
        if type_match:
            score += 10

        if text_similarity >= 0.90:
            score += 35
        elif text_similarity >= 0.80:
            score += 25
        elif text_similarity >= 0.65:
            score += 15

        if body_delta <= 0.08:
            score += 15
        elif body_delta <= 0.20:
            score += 10
        elif body_delta <= 0.35:
            score += 5

        if not title_match and not redirect_match and text_similarity < 0.65:
            weak_signal = True

        if probe_status in [400, 404] and text_similarity < 0.80:
            weak_signal = True
            score = min(score, 45)

        if blocked:
            score = min(score, 35)

        if score > 100:
            score = 100

        return {
            "score": score,
            "status": str(probe_status),
            "length": probe_length,
            "blocked": blocked,
            "weak_signal": weak_signal,
        }

    def _resolve_candidate_ips(self, host):
        candidates = []
        for label in self._candidate_labels(host):
            try:
                infos = socket.getaddrinfo(label, None)
                for info in infos:
                    address = info[4][0]
                    if self._is_ip(address) and address not in candidates:
                        candidates.append(address)
            except socket.gaierror:
                continue
            except Exception as exc:
                self._log("Resolution error for %s: %s" % (label, exc))

        if candidates:
            self._log("Resolved %s -> %s" % (host, ", ".join(candidates)))
        else:
            self._log("Resolved %s -> none" % host)
        return candidates

    def _classify_candidate_score(self, average_score, strong_matches, responses_seen, blocked_count):
        if blocked_count == responses_seen and responses_seen > 0:
            return "RESPONDS_BUT_BLOCKED"
        if responses_seen == 1 and strong_matches == 1 and average_score >= 95:
            return "CONFIRMED_ORIGIN"
        if strong_matches >= 2 and average_score >= 85:
            return "CONFIRMED_ORIGIN"
        if strong_matches >= 1 and average_score >= 75:
            return "LIKELY_ORIGIN"
        if average_score >= 55:
            return "POSSIBLE_ORIGIN"
        return "INCONCLUSIVE"

    def _normalize_request_line(self, request_line, url):
        parts = request_line.split(" ")
        if len(parts) < 3:
            return request_line

        method = parts[0]
        version = parts[-1]
        path = url.getFile() or "/"
        return "%s %s %s" % (method, path, version)

    def _sample_key(self, item, url):
        request_info = self._helpers.analyzeRequest(item)
        method = request_info.getMethod() or "GET"
        path = url.getFile() or "/"
        return "%s %s" % (method, path)

    def _candidate_labels(self, host):
        labels = host.split(".")
        base = self._base_domain(host)
        candidates = [host]

        if base and base not in candidates:
            candidates.append(base)

        for index in range(1, len(labels) - 1):
            candidate = ".".join(labels[index:])
            if "." in candidate and candidate not in candidates and self._candidate_is_reasonable(host, candidate):
                candidates.append(candidate)

        return candidates

    def _candidate_is_reasonable(self, host, candidate):
        host_labels = host.split(".")
        candidate_labels = candidate.split(".")
        if len(candidate_labels) < 2:
            return False
        if len(host_labels) - len(candidate_labels) > 2:
            return False
        return True

    def _base_domain(self, host):
        labels = host.split(".")
        if len(labels) < 2:
            return host
        last_two = ".".join(labels[-2:])
        if len(labels) >= 3 and last_two in self.PUBLIC_SUFFIX_2L:
            return ".".join(labels[-3:])
        return last_two

    def _source_summary(self, samples):
        sources = []
        for sample in samples:
            source = sample["source"]
            if source not in sources:
                sources.append(source)
        return ",".join(sources)

    def _skip_reason(self, url):
        host = (url.getHost() or "").lower()
        if self._scope_only_checkbox.isSelected() and not self._callbacks.isInScope(url):
            return "scope"
        if self._matches_noise_suffix(host):
            return "noise"
        return ""

    def _matches_noise_suffix(self, host):
        for suffix in self.NOISE_SUFFIXES:
            if host == suffix.lstrip(".") or host.endswith(suffix):
                return True
        return False

    def _is_low_signal_host(self, host):
        for suffix in self.LOW_SIGNAL_SUFFIXES:
            if host == suffix.lstrip(".") or host.endswith(suffix):
                return True
        return False

    def _body_text(self, response, response_info):
        body_offset = response_info.getBodyOffset()
        body_bytes = response[body_offset:]
        try:
            return self._helpers.bytesToString(body_bytes)
        except Exception:
            return ""

    def _extract_title(self, body_text):
        match = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
        if not match:
            return ""
        return re.sub(r"\s+", " ", match.group(1)).strip().lower()

    def _normalize_text(self, text):
        text = (text or "").lower()
        text = re.sub(r"<script.*?</script>", " ", text, flags=re.I | re.S)
        text = re.sub(r"<style.*?</style>", " ", text, flags=re.I | re.S)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\b\d+\b", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _text_similarity(self, left, right):
        left_norm = self._normalize_text(left)
        right_norm = self._normalize_text(right)
        if not left_norm or not right_norm:
            return 0.0

        left_tokens = set(left_norm.split(" "))
        right_tokens = set(right_norm.split(" "))
        if not left_tokens or not right_tokens:
            return 0.0

        intersection = len(left_tokens.intersection(right_tokens))
        union = len(left_tokens.union(right_tokens))
        return intersection / float(max(union, 1))

    def _looks_like_direct_ip_block(self, status, body_text, title_text, location):
        combined = " ".join([title_text or "", body_text[:2000] or "", location or ""]).lower()
        markers = [
            "direct ip access",
            "ip access not allowed",
            "request blocked",
            "access denied",
            "forbidden",
            "not allowed",
            "unknown host",
            "default backend",
            "default virtual host",
        ]
        for marker in markers:
            if marker in combined:
                return True

        if status in [401, 403, 421]:
            return True
        return False

    def _get_header_value(self, headers, name):
        prefix = name.lower() + ":"
        for header in headers:
            if header.lower().startswith(prefix):
                return header.split(":", 1)[1].strip()
        return ""

    def _content_type_family(self, value):
        if not value:
            return ""
        return value.split(";", 1)[0].strip().lower()

    def _is_redirect_status(self, status_code):
        return status_code in [301, 302, 303, 307, 308]

    def _redirects_match(self, original_location, probe_location, host):
        if not original_location or not probe_location:
            return False
        return self._normalize_location(original_location, host) == self._normalize_location(
            probe_location, host
        )

    def _normalize_location(self, location, host):
        try:
            parsed = URL(location)
            path = parsed.getPath() or "/"
            query = parsed.getQuery()
            if query:
                path = path + "?" + query

            location_host = parsed.getHost()
            if location_host == host:
                return "host:" + path
            if self._is_ip(location_host):
                return "ip:" + path
            return (location_host or "") + ":" + path
        except Exception:
            if location.startswith("/"):
                return "relative:" + location
            return location

    def _relative_length_delta(self, left, right):
        largest = max(left, right, 1)
        return abs(left - right) / float(largest)

    def _is_ip(self, value):
        if not value:
            return False
        try:
            socket.inet_pton(socket.AF_INET, value)
            return True
        except Exception:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except Exception:
            return False

    def _mark_host_eval_complete(self, host):
        next_host = None
        with self._state_lock:
            if host in self._evaluating_hosts:
                self._evaluating_hosts.remove(host)

            if self._active_evals > 0:
                self._active_evals -= 1

            if self._pending_hosts:
                next_host = self._pending_hosts.pop(0)
                self._active_evals += 1

        if next_host:
            self._run_in_background("origin-eval-beta-" + next_host, self._HostEvaluator(self, next_host))

    def _clear_state(self):
        with self._state_lock:
            self._host_samples = {}
            self._host_rows = {}
            self._visible_rows = {}
            self._evaluating_hosts = set()
            self._pending_hosts = []
            self._active_evals = 0
            self._stats = self._fresh_stats()

        self._refresh_table(None)
        self._log_area.setText("")
        self._log("State cleared")

    def _result_is_likely(self, result):
        return result in self.LIKELY_RESULTS

    def _iter_visible_rows(self):
        with self._state_lock:
            hosts = sorted(self._host_rows.keys())
            rows = [(host, self._host_rows[host]) for host in hosts]

        visible = []
        likely_only = self._likely_only_checkbox.isSelected()
        suppress_low_signal = self._suppress_low_signal_checkbox.isSelected()
        for host, row in rows:
            if self._scope_only_checkbox.isSelected():
                samples = self._host_samples.get(host, [])
                if not self._samples_in_scope(samples):
                    continue
            if likely_only and not self._result_is_likely(row[6]):
                continue
            if suppress_low_signal and self._is_low_signal_host(host) and row[6] in ["INCONCLUSIVE", "POSSIBLE_ORIGIN"]:
                continue
            visible.append((host, row))
        return visible

    def _samples_in_scope(self, samples):
        for sample in samples:
            if self._callbacks.isInScope(sample["url"]):
                return True
        return False

    def _refresh_table(self, _event):
        class TableRefresher(Runnable):
            def __init__(self, extender):
                self._extender = extender

            def run(self):
                while self._extender._table_model.getRowCount() > 0:
                    self._extender._table_model.removeRow(0)

                self._extender._visible_rows = {}
                for host, row in self._extender._iter_visible_rows():
                    row_index = self._extender._table_model.getRowCount()
                    self._extender._table_model.addRow(row)
                    self._extender._visible_rows[host] = row_index

        SwingUtilities.invokeLater(TableRefresher(self))

    def _on_filter_changed(self, _event):
        self._refresh_table(None)
        self._log(
            "Filters updated: only_in_scope=%s only_likely_origin=%s suppress_low_signal=%s active_probing=%s"
            % (
                "on" if self._scope_only_checkbox.isSelected() else "off",
                "on" if self._likely_only_checkbox.isSelected() else "off",
                "on" if self._suppress_low_signal_checkbox.isSelected() else "off",
                "on" if self._active_probe_checkbox.isSelected() else "off",
            )
        )

    def _log(self, message):
        class LogAppender(Runnable):
            def __init__(self, extender, text):
                self._extender = extender
                self._text = text

            def run(self):
                self._extender._log_area.append("[*] " + self._text + "\n")

        SwingUtilities.invokeLater(LogAppender(self, message))
        print("[OriginIpAutoDetect Beta] %s" % message)

    def _run_in_background(self, name, runnable):
        worker = Thread(runnable, name)
        worker.setDaemon(True)
        worker.start()

    class _HistoryImporter(Runnable):
        def __init__(self, extender, force=False, reset_run_stats=False):
            self._extender = extender
            self._force = force
            self._reset_run_stats = reset_run_stats

        def run(self):
            self._extender._import_proxy_history(self._force, self._reset_run_stats)

    class _MessageProcessor(Runnable):
        def __init__(self, extender, item, from_history, source_label):
            self._extender = extender
            self._item = item
            self._from_history = from_history
            self._source_label = source_label

        def run(self):
            self._extender._process_item(self._item, self._from_history, self._source_label)

    class _HostEvaluator(Runnable):
        def __init__(self, extender, host):
            self._extender = extender
            self._host = host

        def run(self):
            self._extender._evaluate_host(self._host)


class ResultCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, column):
        component = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )

        if isSelected:
            return component

        result = str(table.getValueAt(row, 6))
        component.setForeground(Color.BLACK)

        if result == "CONFIRMED_ORIGIN":
            component.setBackground(Color(229, 57, 53))
            component.setForeground(Color.WHITE)
        elif result == "LIKELY_ORIGIN":
            component.setBackground(Color(251, 140, 0))
            component.setForeground(Color.WHITE)
        elif result == "RESPONDS_BUT_BLOCKED":
            component.setBackground(Color(109, 76, 65))
            component.setForeground(Color.WHITE)
        else:
            component.setBackground(Color.WHITE)

        return component


def java_array_list():
    from java.util import ArrayList

    return ArrayList()
