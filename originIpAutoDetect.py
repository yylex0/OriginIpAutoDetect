from burp import (
    IBurpExtender,
    IHttpListener,
    IScannerCheck,
    IScanIssue,
    IExtensionStateListener,
    ITab,
    IContextMenuFactory,
)

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

from threading import Lock, Event
import difflib
import re
import socket
import struct
import time


class BurpExtender(
    IBurpExtender,
    IHttpListener,
    IScannerCheck,
    IExtensionStateListener,
    ITab,
    IContextMenuFactory,
):
    MAX_SAMPLES_PER_HOST = 5
    MAX_CONCURRENT_EVAL = 5
    MAX_CANDIDATE_IPS = 6
    MAX_BODY_BYTES = 262144          # cap raw bytes retained per sample (256 KiB)
    SIMILARITY_SAMPLE_CHARS = 2000   # cap for the O(n^2) sequence comparison (perf bound)
    WORKER_JOIN_TIMEOUT_MS = 2000

    # Verdicts that represent a positive origin lead (used by the "Only Likely" filter / scanner issues).
    LIKELY_RESULTS = ["CONFIRMED_ORIGIN", "PROBABLE_ORIGIN", "LIKELY_ORIGIN", "POSSIBLE_ORIGIN"]
    # Only CONFIRMED_ORIGIN raises a Burp Scanner issue. PROBABLE / LIKELY / POSSIBLE are
    # leads for manual review and stay in the extension tab only, to keep the Scanner clean.
    ISSUE_RESULTS = ["CONFIRMED_ORIGIN"]

    PUBLIC_SUFFIX_2L = set([
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "co.in", "org.in", "net.in", "gov.in",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "net.br", "org.br",
    ])
    NOISE_SUFFIXES = [
        ".google.com", ".googleapis.com", ".gstatic.com", ".doubleclick.net",
        ".googletagmanager.com", ".google-analytics.com", ".googlesyndication.com",
        ".facebook.com", ".facebook.net", ".fbcdn.net", ".cloudfront.net",
        ".akamaihd.net", ".akamaized.net", ".jsdelivr.net", ".bootstrapcdn.com",
        ".fontawesome.com", ".cloudflare.com", ".cloudflareinsights.com",
        ".sentry.io", ".segment.io", ".hotjar.com",
    ]
    LOW_SIGNAL_SUFFIXES = [
        ".google.com", ".google.co.in", ".google.co.uk",
        ".linkedin.com", ".g2.com", ".piwik.pro", ".stackadapt.com",
    ]

    # Content types we analyse. Everything else (images, fonts, css, js, media, binaries)
    # is skipped before any probing -- origin detection only needs document-like bodies.
    ANALYZABLE_TYPES = [
        "text/html", "application/xhtml", "application/json",
        "text/plain", "application/xml", "text/xml",
    ]
    SKIP_TYPES = [
        "image/", "font/", "video/", "audio/", "text/css",
        "application/javascript", "text/javascript", "application/octet-stream",
        "application/pdf", "application/zip", "application/font", "application/wasm",
    ]

    # CDN / reverse-proxy fingerprints, split by confidence. A CDN signal is used only to
    # DOWNGRADE a candidate away from CONFIRMED (edge != origin), never to prove origin.
    #   STRONG = CDN-specific, not emitted by ordinary origins -> treat candidate as edge.
    #   WEAK   = cache/proxy headers also produced by plain origins (Varnish, nginx proxy
    #            cache, squid) -> annotate only, do NOT force a CDN verdict.
    CDN_STRONG_HEADERS = [
        "cf-ray:", "cf-cache-status:", "cf-connecting-ip:", "x-amz-cf-id:",
        "x-amz-cf-pop:", "fastly-", "x-akamai", "akamai-", "x-azure-ref:",
        "x-msedge-ref:", "x-sucuri-id:", "x-sucuri-cache:", "x-iinfo:",
    ]
    CDN_WEAK_HEADERS = ["x-cache:", "x-served-by:", "x-cdn:", "x-edge-", "x-varnish:"]
    CDN_STRONG_SERVER = [
        "cloudflare", "akamaighost", "cloudfront", "fastly",
        "sucuri", "incapsula", "imperva",
    ]
    CDN_WEAK_SERVER = ["varnish", "ecacc", "ecd", "akamai"]
    CDN_STRONG_VIA = ["cloudfront", "fastly", "akamai"]   # a CDN named in Via
    CDN_WEAK_VIA = ["varnish", "squid"]
    # Compact, best-effort CDN IPv4 ranges (may age -- used only as a supporting signal).
    CDN_CIDRS = [
        "104.16.0.0/13", "172.64.0.0/13", "131.0.72.0/22", "108.162.192.0/18",
        "162.158.0.0/15", "173.245.48.0/20", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "141.101.64.0/18",   # Cloudflare
        "151.101.0.0/16",                                            # Fastly
        "23.235.32.0/20", "43.249.72.0/22",                          # Fastly
    ]

    # ------------------------------------------------------------------ lifecycle
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self._callbacks.setExtensionName("OriginIpAutoDetect")
        self._init_state()

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerScannerCheck(self)
        self._callbacks.registerContextMenuFactory(self)
        self._callbacks.registerExtensionStateListener(self)

        self._cdn_networks = self._parse_cidrs(self.CDN_CIDRS)

        self._build_ui()
        self._callbacks.addSuiteTab(self)

        # NOTE: proxy history is NOT imported automatically (keeps startup cheap on large
        # projects). Use the "Import HTTP History" button when you want it.
        self._log("Extension loaded. Browse the target, or use Import HTTP History / Site Map.")

    def _init_state(self):
        self._host_samples = {}
        self._host_rows = {}
        self._host_verdict = {}      # host -> dict used by the scanner check (no re-probing)
        self._host_evidence = {}     # host -> explainable evidence record
        self._visible_rows = {}
        self._evaluating_hosts = set()
        self._pending_hosts = []
        self._active_evals = 0
        self._history_import_started = False
        self._state_lock = Lock()
        self._workers = []
        self._workers_lock = Lock()
        self._shutdown = Event()
        self._stats = self._fresh_stats()

    def extensionUnloaded(self):
        # Signal every worker to stop, then join in-flight threads so no probe fires after unload.
        self._shutdown.set()
        with self._workers_lock:
            workers = list(self._workers)
        for worker in workers:
            try:
                if worker.isAlive():
                    worker.join(self.WORKER_JOIN_TIMEOUT_MS)
            except Exception:
                pass
        try:
            self._callbacks.printOutput("OriginIpAutoDetect unloaded; background workers stopped.")
        except Exception:
            pass

    def getTabCaption(self):
        return "OriginIpAutoDetect"

    def getUiComponent(self):
        return self._ui

    # ------------------------------------------------------------------ context menu
    def createMenuItems(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return None
        menu_items = java_array_list()
        menu_items.add(
            JMenuItem(
                "Send to OriginIpAutoDetect",
                actionPerformed=lambda event: self._run_in_background(
                    "origin-menu-import", self._MessageImporter(self, messages, "selection")
                ),
            )
        )
        return menu_items

    # ------------------------------------------------------------------ passive capture
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or self._shutdown.is_set():
            return
        if toolFlag != self._callbacks.TOOL_PROXY:
            return
        self._run_in_background(
            "origin-live-response",
            self._MessageProcessor(self, messageInfo, False, "live"),
        )

    # ------------------------------------------------------------------ scanner integration
    # We do NOT probe inside doPassiveScan (that would make passive scanning expensive).
    # Instead we surface an issue when our own pipeline has ALREADY reached a positive
    # verdict for this host, so the finding shows up in the Scanner dashboard and the
    # scan queue, with deduplication handled by consolidateDuplicateIssues().
    def doPassiveScan(self, baseRequestResponse):
        try:
            if self._shutdown.is_set():
                return None
            request_info = self._helpers.analyzeRequest(baseRequestResponse)
            url = request_info.getUrl()
            if not url:
                return None
            host = (url.getHost() or "").lower()
            with self._state_lock:
                verdict = self._host_verdict.get(host)
            if not verdict or verdict["result"] not in self.ISSUE_RESULTS:
                return None
            return [self._build_scan_issue(baseRequestResponse, url, verdict)]
        except Exception as exc:
            self._report_error("doPassiveScan failed", exc)
            return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Origin detection is host-level, not insertion-point-level. Burp calls this once per
        # insertion point; we compute the verdict ONCE per host (first call) and serve the
        # cached verdict thereafter, so a request with many insertion points triggers a single
        # probe pass. Duplicate issues are collapsed by consolidateDuplicateIssues().
        try:
            if self._shutdown.is_set():
                return None
            request_info = self._helpers.analyzeRequest(baseRequestResponse)
            url = request_info.getUrl()
            host = (url.getHost() or "").lower()
            if not host or self._is_ip(host) or self._skip_reason(url):
                return None

            with self._state_lock:
                verdict = self._host_verdict.get(host)
            if verdict is None:
                verdict = self._active_scan_host(baseRequestResponse, url, host)
            if verdict and verdict["result"] in self.ISSUE_RESULTS:
                return [self._build_scan_issue(baseRequestResponse, url, verdict)]
            return None
        except Exception as exc:
            self._report_error("doActiveScan failed", exc)
            return None

    def _active_scan_host(self, baseRequestResponse, url, host):
        # Evaluate a host synchronously for an active scan, reusing any samples already
        # captured for it plus this request. Does NOT touch the passive scheduler.
        response = self._trim_bytes(baseRequestResponse.getResponse())
        request = baseRequestResponse.getRequest()
        if not request or not response or not self._is_analyzable_response(response):
            return None
        local_sample = {
            "key": self._sample_key(baseRequestResponse, url), "item": baseRequestResponse,
            "url": url, "request": request, "response": response, "source": "active-scan",
        }
        with self._state_lock:
            samples = list(self._host_samples.get(host, []))
        keys = set([s["key"] for s in samples])
        if local_sample["key"] not in keys:
            samples = samples + [local_sample]
        samples = samples[: self.MAX_SAMPLES_PER_HOST]

        candidate_ips = self._resolve_candidate_ips(host)
        best = self._post_process_verdict(host, self._probe_candidates(host, samples, candidate_ips))
        evidence = self._attach_provenance(host, best)
        scheme = url.getProtocol() or "http"
        port = url.getPort()
        if port == -1:
            port = 443 if scheme == "https" else 80
        row = [
            host, self._base_domain(host), scheme, port,
            ", ".join(candidate_ips) if candidate_ips else "unresolved",
            best["origin_ip"], best["result"], best["score"], best["matches"],
            best["probe_status"], best["probe_length"], "active-scan", best["notes"],
        ]
        verdict = {
            "result": best["result"], "score": best["score"], "matches": best["matches"],
            "origin_ip": best["origin_ip"], "notes": best["notes"],
        }
        with self._state_lock:
            self._host_rows[host] = row
            self._host_verdict[host] = verdict
            if evidence:
                self._host_evidence[host] = evidence
        self._refresh_table(None)
        return verdict

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        try:
            if (existingIssue.getIssueName() == newIssue.getIssueName()
                    and existingIssue.getUrl().getHost() == newIssue.getUrl().getHost()):
                return -1   # keep existing, drop duplicate
        except Exception:
            pass
        return 0

    def _build_scan_issue(self, base, url, verdict):
        with self._state_lock:
            evidence = self._host_evidence.get((url.getHost() or "").lower())
        evidence_html = ""
        if evidence:
            rows = []
            if evidence.get("provenance"):
                rows.append("Discovered via: %s" % self._html_escape(evidence["provenance"]))
            rows.append("Assessment: %s" % self._html_escape(evidence.get("accessibility", "")))
            for item in evidence.get("cdn_indicators", []):
                rows.append("[CDN] %s" % self._html_escape(item))
            for item in evidence.get("for", []):
                rows.append("[+] %s" % self._html_escape(item))
            for item in evidence.get("against", []):
                rows.append("[-] %s" % self._html_escape(item))
            evidence_html = "<br><b>Evidence</b><br>" + "<br>".join(rows)
        detail = (
            "OriginIpAutoDetect classified host <b>%s</b> as <b>%s</b> (score %s, matches %s).<br><br>"
            "Candidate origin IP: <b>%s</b><br>Notes: %s<br>%s<br>"
            "This indicates the application may be reachable directly at the candidate IP, "
            "bypassing the fronting CDN/WAF. Verify manually before relying on this result."
            % (
                self._html_escape(url.getHost()), verdict["result"], verdict["score"],
                verdict["matches"], self._html_escape(verdict["origin_ip"] or "n/a"),
                self._html_escape(verdict["notes"] or "none"), evidence_html,
            )
        )
        severity = "Medium"      # origin exposure = WAF/CDN bypass risk
        confidence = "Firm"      # only CONFIRMED_ORIGIN reaches this point
        return CustomScanIssue(
            base.getHttpService(), url, [base], "Potential origin IP exposure",
            detail, severity, confidence,
            "The server behind a CDN/WAF may be directly reachable by IP, allowing an "
            "attacker to bypass edge protections (WAF rules, rate limiting, DDoS mitigation).",
            "Restrict the origin to accept traffic only from the CDN/WAF (IP allow-listing, "
            "mTLS, or shared-secret header validation).",
        )

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        columns = [
            "Host", "Base Domain", "Scheme", "Port", "Candidate IPs", "Origin IP",
            "Result", "Score", "Matches", "Probe Status", "Probe Length", "Sources", "Notes",
        ]
        self._columns = columns
        self._table_model = DefaultTableModel(columns, 0)
        self._table = JTable(self._table_model)
        self._table.setDefaultRenderer(Object, ResultCellRenderer())

        self._log_area = JTextArea()
        self._log_area.setEditable(False)

        controls = JPanel(FlowLayout(FlowLayout.LEFT))
        self._scope_only_checkbox = JCheckBox("Only In Scope", False, actionPerformed=self._on_filter_changed)
        self._likely_only_checkbox = JCheckBox("Only Likely Origin", False, actionPerformed=self._on_filter_changed)
        self._suppress_low_signal_checkbox = JCheckBox("Suppress Low Signal", True, actionPerformed=self._on_filter_changed)
        self._active_probe_checkbox = JCheckBox("Enable Active Probing", True, actionPerformed=self._on_filter_changed)
        self._site_map_targets = JTextField(30)

        load_history_button = JButton(
            "Import HTTP History",
            actionPerformed=lambda event: self._run_in_background(
                "origin-manual-history",
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

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self._table), JScrollPane(self._log_area))
        split.setResizeWeight(0.72)

        panel = JPanel(BorderLayout())
        panel.add(controls, BorderLayout.NORTH)
        panel.add(split, BorderLayout.CENTER)

        self._ui = panel
        self._callbacks.customizeUiComponent(self._ui)

    def _fresh_stats(self):
        return {
            "seen": 0, "added": 0, "skipped_ip": 0, "skipped_scope": 0,
            "skipped_noise": 0, "skipped_type": 0, "skipped_duplicate": 0, "hosts_evaluated": 0,
        }

    # ------------------------------------------------------------------ import paths
    def _import_site_map_targets(self):
        raw_targets = self._site_map_targets.getText().strip()
        prefixes = [item.strip() for item in raw_targets.split(",") if item.strip()]
        if not prefixes:
            JOptionPane.showMessageDialog(
                self._dialog_parent(),
                "Enter one or more site map prefixes, separated by commas.",
                "OriginIpAutoDetect", JOptionPane.INFORMATION_MESSAGE,
            )
            return
        # Heavy work (getSiteMap + import) runs off the EDT so the UI never freezes.
        self._run_in_background("origin-site-map", self._SiteMapImporter(self, prefixes))

    def _do_import_site_map(self, prefixes):
        total = 0
        for prefix in prefixes:
            if self._shutdown.is_set():
                return
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
            "History summary: seen=%d added=%d evaluated=%d skipped_ip=%d skipped_scope=%d "
            "skipped_noise=%d skipped_type=%d skipped_duplicate=%d"
            % (self._stats["seen"], self._stats["added"], self._stats["hosts_evaluated"],
               self._stats["skipped_ip"], self._stats["skipped_scope"], self._stats["skipped_noise"],
               self._stats["skipped_type"], self._stats["skipped_duplicate"])
        )
        self._log("Proxy history import complete")

    def _import_messages(self, messages, source_label, from_history=False):
        added = 0
        for item in messages:
            if self._shutdown.is_set():
                break
            if self._process_item(item, from_history, source_label):
                added += 1
        if not from_history:
            self._log("Imported %d messages from %s" % (added, source_label))

    def _process_item(self, item, from_history, source_label):
        try:
            if from_history:
                with self._state_lock:
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
                self._bump("skipped_ip", from_history)
                return False

            skip_reason = self._skip_reason(url)
            if skip_reason:
                if skip_reason == "scope":
                    self._bump("skipped_scope", from_history)
                elif skip_reason == "noise":
                    self._bump("skipped_noise", from_history)
                return False

            if not self._is_analyzable_response(response):
                self._bump("skipped_type", from_history)
                return False

            return self._record_sample(item, url, request, response, source_label, from_history)
        except Exception as exc:
            self._report_error("Failed to process %s item" % source_label, exc)
            return False

    def _bump(self, key, from_history):
        if not from_history:
            return
        with self._state_lock:
            self._stats[key] += 1

    def _record_sample(self, item, url, request, response, source_label, from_history):
        host = (url.getHost() or "").lower()
        sample_key = self._sample_key(item, url)
        response = self._trim_bytes(response)

        with self._state_lock:
            samples = self._host_samples.get(host)
            if samples is None:
                samples = []
                self._host_samples[host] = samples

            for sample in samples:
                if sample["key"] == sample_key:
                    self._bump_locked("skipped_duplicate", from_history)
                    return False
            if len(samples) >= self.MAX_SAMPLES_PER_HOST:
                self._bump_locked("skipped_duplicate", from_history)
                return False

            samples.append({
                "key": sample_key, "item": item, "url": url,
                "request": request, "response": response, "source": source_label,
            })
            self._bump_locked("added", from_history)

            if host in self._evaluating_hosts:
                return True
            self._evaluating_hosts.add(host)

        self._schedule_host_evaluation(host)
        return True

    def _bump_locked(self, key, from_history):
        if from_history:
            self._stats[key] += 1

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
            self._run_in_background("origin-eval-" + host, self._HostEvaluator(self, host))

    # ------------------------------------------------------------------ evaluation
    def _evaluate_host(self, host):
        try:
            if self._shutdown.is_set():
                return
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
            evidence = self._attach_provenance(host, best)

            row = [
                host, self._base_domain(host), scheme, port,
                ", ".join(candidate_ips) if candidate_ips else "unresolved",
                best["origin_ip"], best["result"], best["score"], best["matches"],
                best["probe_status"], best["probe_length"], self._source_summary(samples), best["notes"],
            ]
            with self._state_lock:
                self._host_rows[host] = row
                self._host_verdict[host] = {
                    "result": best["result"], "score": best["score"], "matches": best["matches"],
                    "origin_ip": best["origin_ip"], "notes": best["notes"],
                }
                if evidence:
                    self._host_evidence[host] = evidence
                self._stats["hosts_evaluated"] += 1

            self._refresh_table(None)
            if evidence:
                self._log(self._format_evidence(host, evidence))
            self._log(
                "Source=%s Host=%s BaseDomain=%s Port=%s Candidates=%s OriginIP=%s Result=%s "
                "Score=%s Matches=%s Status=%s Length=%s Notes=%s"
                % (row[11], host, row[1], port, row[4], row[5] if row[5] else "none",
                   row[6], row[7], row[8], row[9], row[10], row[12] if row[12] else "none")
            )
        except Exception as exc:
            self._report_error("Evaluation failed for %s" % host, exc)
        finally:
            self._mark_host_eval_complete(host)

    def _probe_candidates(self, host, samples, candidate_ips):
        if not self._active_probe_checkbox.isSelected():
            return self._empty_verdict("PROBING_DISABLED", "disabled", 0, "Active probing disabled")
        if not candidate_ips:
            return self._empty_verdict("UNRESOLVED", "unresolved", 0, "DNS did not resolve")

        best = None
        for ip in candidate_ips:
            if self._shutdown.is_set():
                break
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
            "origin_ip": "", "result": label, "score": "0/100", "score_value": 0,
            "matches": "0/0", "probe_status": probe_status, "probe_length": probe_length,
            "notes": notes, "blocked_ratio": 0.0, "cdn": False,
        }

    def _evaluate_candidate(self, host, ip, samples):
        total_score = 0.0
        strong_matches = 0
        responses_seen = 0
        blocked_count = 0
        discriminator_hits = 0
        content_hits = 0
        catchall_hits = 0
        weak_signal_count = 0
        no_response_https = 0
        last_status = "no-response"
        last_length = 0
        cdn_detected = False
        cdn_marker = ""
        weak_cdn_marker = ""
        best_content_sim = 0.0
        signal_counts = {"status": 0, "title": 0, "redirect": 0, "server": 0,
                         "ctype": 0, "strong_body": 0}
        cdn_indicators = []

        ip_is_cdn, ip_cdn_note = self._ip_in_cdn_range(ip)
        if ip_is_cdn:
            cdn_detected = True
            cdn_marker = ip_cdn_note
            cdn_indicators.append("candidate IP %s is inside a known CDN range" % ip)

        for sample in samples:
            if self._shutdown.is_set():
                break
            original_host = (sample["url"].getHost() or "").lower()

            # host=domain is the authoritative origin test: "does this IP serve OUR app
            # when asked for our hostname?". host=ip is only used to detect a catch-all /
            # default vhost (shared hosting), never to inflate the score.
            domain_response = self._send_probe_request(sample["item"], sample["url"], sample["request"], ip, original_host)
            ip_response = self._send_probe_request(sample["item"], sample["url"], sample["request"], ip, ip)

            if not domain_response:
                if self._is_https_sample(sample):
                    no_response_https += 1
                continue

            cmp_domain = self._compare_response_pair(sample["url"], sample["response"], domain_response)
            responses_seen += 1
            total_score += cmp_domain["score"]
            last_status = cmp_domain["status"]
            last_length = cmp_domain["length"]
            if cmp_domain["content_sim"] > best_content_sim:
                best_content_sim = cmp_domain["content_sim"]
            for key in signal_counts:
                if cmp_domain.get("signals", {}).get(key):
                    signal_counts[key] += 1

            # CDN signal on either side. A STRONG (CDN-specific) signal marks the candidate
            # as edge infrastructure; a WEAK one (cache header a plain origin can also send)
            # is only annotated and never forces a CDN verdict.
            strength, marker = self._cdn_signal(sample["response"])
            where = "original"
            if not strength:
                strength, marker = self._cdn_signal(domain_response)
                where = "probe"
            if strength == "strong":
                cdn_detected = True
                if not cdn_marker:
                    cdn_marker = marker
                indicator = "%s (seen on %s response)" % (marker, where)
                if indicator not in cdn_indicators:
                    cdn_indicators.append(indicator)
            elif strength == "weak" and not weak_cdn_marker:
                weak_cdn_marker = marker

            if cmp_domain["blocked"]:
                blocked_count += 1
            if cmp_domain["weak_signal"]:
                weak_signal_count += 1
            if cmp_domain["score"] >= 75:
                strong_matches += 1
            if cmp_domain["discriminator"]:
                discriminator_hits += 1
            if cmp_domain["content_sim"] >= 0.50:
                content_hits += 1

            # Catch-all check: if Host:ip returns essentially the same body as Host:domain
            # AND that body only weakly matches the original, the IP is a generic default
            # vhost that answers anything -> shared-hosting false-positive risk.
            if ip_response and not cmp_domain["discriminator"]:
                if self._bodies_equivalent(domain_response, ip_response):
                    catchall_hits += 1

        if responses_seen == 0:
            if no_response_https > 0:
                return {
                    "origin_ip": ip, "result": "INCONCLUSIVE", "score": "0/100", "score_value": 0,
                    "matches": "0/0", "probe_status": "no-tls-response", "probe_length": 0,
                    "notes": "https probe returned nothing (possible SNI-enforced origin; see limitations)",
                    "blocked_ratio": 0.0, "cdn": cdn_detected,
                    "evidence": {
                        "ip": ip, "samples": len(samples), "responses": 0,
                        "for": [], "cdn_indicators": list(cdn_indicators),
                        "against": ["no HTTPS response from candidate (handshake refused / SNI-enforced origin)"],
                        "accessibility": "unreachable-as-probed",
                    },
                }
            return None

        average_score = int(total_score / float(responses_seen))
        has_discriminator = discriminator_hits > 0
        has_content = content_hits > 0
        result = self._classify_candidate_score(
            average_score, strong_matches, responses_seen, blocked_count,
            cdn_detected, has_discriminator, has_content,
        )
        evidence = self._build_evidence(
            ip, samples, responses_seen, average_score, strong_matches, signal_counts,
            best_content_sim, has_discriminator, content_hits, catchall_hits, blocked_count,
            cdn_detected, cdn_indicators, weak_cdn_marker, result,
        )
        return {
            "origin_ip": ip,
            "result": result,
            "score": "%d/100" % average_score,
            "score_value": average_score,
            "matches": "%d/%d" % (strong_matches, responses_seen),
            "probe_status": last_status,
            "probe_length": last_length,
            "notes": self._candidate_notes(blocked_count, responses_seen, weak_signal_count,
                                           catchall_hits, cdn_detected, cdn_marker,
                                           weak_cdn_marker, has_discriminator),
            "blocked_ratio": blocked_count / float(max(responses_seen, 1)),
            "catchall_ratio": catchall_hits / float(max(responses_seen, 1)),
            "cdn": cdn_detected,
            "evidence": evidence,
        }

    def _build_evidence(self, ip, samples, responses_seen, average_score, strong_matches,
                        signal_counts, best_content_sim, has_discriminator, content_hits,
                        catchall_hits, blocked_count, cdn_detected, cdn_indicators,
                        weak_cdn_marker, result):
        # Explainable per-candidate record: what supports the verdict, what argues against it,
        # and the honest accessibility-vs-origin distinction. Surfaced in the Scanner issue
        # and the log so a user never has to read the source to understand a classification.
        total = responses_seen
        ev_for = []
        ev_against = []
        if signal_counts["redirect"]:
            ev_for.append("redirect target matched original on %d/%d samples" % (signal_counts["redirect"], total))
        if signal_counts["strong_body"]:
            ev_for.append("strong body similarity (>=0.85) on %d/%d samples" % (signal_counts["strong_body"], total))
        if signal_counts["title"]:
            ev_for.append("<title> matched on %d/%d samples" % (signal_counts["title"], total))
        if signal_counts["status"]:
            ev_for.append("HTTP status matched on %d/%d samples" % (signal_counts["status"], total))
        if signal_counts["server"]:
            ev_for.append("Server header matched on %d/%d samples" % (signal_counts["server"], total))
        if signal_counts["ctype"]:
            ev_for.append("Content-Type family matched on %d/%d samples" % (signal_counts["ctype"], total))
        ev_for.append("best content similarity %.2f; %d/%d strong sample(s)" % (best_content_sim, strong_matches, total))

        if not has_discriminator:
            ev_against.append("no discriminator: only generic HTTP shape matched (not application-identifying)")
        if catchall_hits:
            ev_against.append("Host:IP default vhost returns the same body (catch-all) on %d/%d samples" % (catchall_hits, total))
        if blocked_count:
            ev_against.append("%d/%d probes looked blocked (WAF/direct-IP block)" % (blocked_count, total))
        if best_content_sim < 0.50:
            ev_against.append("body overlap is weak (%.2f)" % best_content_sim)
        if weak_cdn_marker and not cdn_detected:
            ev_against.append("weak cache/proxy header present (%s) - noted, not treated as CDN" % weak_cdn_marker)

        # Honest A/B/C distinction.
        if cdn_detected:
            accessibility = "serves the application, but candidate is CDN/edge infrastructure (not the origin)"
        elif result in ("CONFIRMED_ORIGIN", "PROBABLE_ORIGIN", "LIKELY_ORIGIN"):
            accessibility = "candidate serves the target application directly (direct-access evidence; verify manually)"
        elif result == "POSSIBLE_ORIGIN":
            accessibility = "candidate responds with some matching content; direct origin not established"
        else:
            accessibility = "candidate responds but does not demonstrably serve the target application"

        return {
            "ip": ip, "samples": len(samples), "responses": responses_seen,
            "avg_score": average_score, "strong_matches": strong_matches,
            "best_content_sim": round(best_content_sim, 3),
            "for": ev_for, "against": ev_against,
            "cdn_indicators": list(cdn_indicators),
            "accessibility": accessibility, "verdict": result,
            "provenance": "",   # filled by caller (how the IP was discovered)
        }

    def _attach_provenance(self, host, best):
        evidence = best.get("evidence") if best else None
        if not evidence:
            return None
        evidence["provenance"] = ("DNS (getaddrinfo) of %s and related labels; base domain %s"
                                  % (host, self._base_domain(host)))
        return evidence

    def _format_evidence(self, host, evidence):
        if not evidence:
            return ""
        lines = ["Evidence for %s -> candidate %s [%s]" % (host, evidence.get("ip", "?"), evidence.get("verdict", "?"))]
        if evidence.get("provenance"):
            lines.append("  Discovered via: %s" % evidence["provenance"])
        lines.append("  Samples probed: %s; responses: %s; avg score: %s; strong: %s; best body sim: %s"
                     % (evidence.get("samples"), evidence.get("responses"), evidence.get("avg_score"),
                        evidence.get("strong_matches"), evidence.get("best_content_sim")))
        lines.append("  Assessment: %s" % evidence.get("accessibility", ""))
        for item in evidence.get("cdn_indicators", []):
            lines.append("  [CDN] %s" % item)
        for item in evidence.get("for", []):
            lines.append("  [+] %s" % item)
        for item in evidence.get("against", []):
            lines.append("  [-] %s" % item)
        return "\n".join(lines)

    def _classify_candidate_score(self, average_score, strong_matches, responses_seen,
                                  blocked_count, cdn_detected, has_discriminator, has_content):
        if blocked_count == responses_seen and responses_seen > 0:
            return "RESPONDS_BUT_BLOCKED"
        # A CDN/edge that serves the app is NOT the origin, regardless of how well it matches.
        if cdn_detected:
            return "RESPONDS_VIA_CDN" if average_score >= 55 else "INCONCLUSIVE"
        # Origin-claiming verdicts require a real discriminator (redirect / strong structural
        # match / title+content), not just generic HTTP shape (status+server+type+length).
        if has_discriminator:
            if strong_matches >= 2 and average_score >= 85:
                return "CONFIRMED_ORIGIN"            # needs >=2 corroborating samples
            if strong_matches >= 1 and average_score >= 75:
                return "PROBABLE_ORIGIN"             # single strong sample: probable, not confirmed
            if average_score >= 70:
                return "LIKELY_ORIGIN"
        # POSSIBLE requires at least a real content signal; a pure HTTP-shape match
        # (status + Server + Content-Type + length, with near-zero body overlap) is noise.
        if average_score >= 55 and has_content:
            return "POSSIBLE_ORIGIN"
        return "INCONCLUSIVE"

    def _candidate_notes(self, blocked_count, responses_seen, weak_signal_count,
                         catchall_hits, cdn_detected, cdn_marker, weak_cdn_marker, has_discriminator):
        notes = []
        if cdn_detected:
            notes.append("cdn/edge" + ((":" + cdn_marker) if cdn_marker else ""))
        elif weak_cdn_marker:
            notes.append("cache/proxy-header:" + weak_cdn_marker + " (not treated as CDN)")
        if not has_discriminator:
            notes.append("no-discriminator(shape-only match)")
        if catchall_hits:
            notes.append("catch-all-vhost=%d/%d" % (catchall_hits, responses_seen))
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
            if result in ("POSSIBLE_ORIGIN", "LIKELY_ORIGIN"):
                result = "INCONCLUSIVE"
            elif result in ("PROBABLE_ORIGIN", "CONFIRMED_ORIGIN") and score_value < 90:
                result = "POSSIBLE_ORIGIN"

        if verdict.get("blocked_ratio", 0.0) >= 0.5 and result in (
                "POSSIBLE_ORIGIN", "LIKELY_ORIGIN", "PROBABLE_ORIGIN"):
            result = "RESPONDS_BUT_BLOCKED"
            notes.append("Possible origin behind WAF/CDN")

        if verdict["notes"]:
            notes.append(verdict["notes"])

        verdict["result"] = result
        verdict["notes"] = ", ".join([note for note in notes if note])
        return verdict

    # ------------------------------------------------------------------ probing
    def _send_probe_request(self, item, url, request, ip, host_header):
        if self._shutdown.is_set():
            return None
        request_bytes = self._build_ip_request(item, url, request, host_header)
        service = item.getHttpService()
        port = service.getPort()
        protocol = service.getProtocol()
        try:
            response_wrapper = self._callbacks.makeHttpRequest(
                self._helpers.buildHttpService(ip, port, protocol), request_bytes
            )
            if response_wrapper and response_wrapper.getResponse():
                return response_wrapper.getResponse()
        except Exception as exc:
            self._log("Probe error for %s via %s over %s: %s" % (url.getHost(), ip, protocol, exc))

        if str(protocol).lower() == "https" and not self._shutdown.is_set():
            try:
                fallback_wrapper = self._callbacks.makeHttpRequest(
                    self._helpers.buildHttpService(ip, 80, "http"), request_bytes
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

    # ------------------------------------------------------------------ comparison / scoring
    def _compare_response_pair(self, url, original_response, probe_response):
        probe_info = self._helpers.analyzeResponse(probe_response)
        probe_status = probe_info.getStatusCode()
        probe_length = len(probe_response)

        if not original_response:
            return {
                "score": 20, "status": str(probe_status), "length": probe_length,
                "blocked": False, "weak_signal": True, "content_sim": 0.0, "discriminator": False,
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
        type_match = (bool(original_type)
                      and self._content_type_family(original_type) == self._content_type_family(probe_type))
        redirect_match = self._redirects_match(original_location, probe_location, url.getHost())
        content_sim = self._content_similarity(original_body, probe_body)
        body_delta = self._relative_length_delta(len(original_body), len(probe_body))
        blocked = self._looks_like_direct_ip_block(probe_status, probe_body, probe_title, probe_location)

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

        if content_sim >= 0.90:
            score += 35
        elif content_sim >= 0.80:
            score += 25
        elif content_sim >= 0.65:
            score += 15
        elif content_sim >= 0.50:
            score += 5

        if body_delta <= 0.08:
            score += 15
        elif body_delta <= 0.20:
            score += 10
        elif body_delta <= 0.35:
            score += 5

        weak_signal = (not title_match and not redirect_match and content_sim < 0.50)
        if probe_status in [400, 404] and content_sim < 0.80:
            weak_signal = True
            score = min(score, 45)
        if blocked:
            score = min(score, 35)
        if score > 100:
            score = 100

        # A discriminator is evidence BEYOND generic HTTP shape -- something that ties the
        # probe to THIS specific application: a matching redirect target, strong structural
        # body similarity, or a matching title backed by real content overlap.
        discriminator = (
            redirect_match
            or content_sim >= 0.85
            or (title_match and content_sim >= 0.75)
        )
        return {
            "score": score, "status": str(probe_status), "length": probe_length,
            "blocked": blocked, "weak_signal": weak_signal,
            "content_sim": content_sim, "discriminator": discriminator,
            "signals": {
                "status": status_match, "title": title_match, "redirect": redirect_match,
                "server": server_match, "ctype": type_match, "strong_body": content_sim >= 0.85,
            },
        }

    def _content_similarity(self, left, right):
        # Combine structural (order-sensitive) and token-set similarity. Pure token-set
        # (Jaccard) over-scores unrelated pages that share boilerplate chrome; the sequence
        # ratio penalises different page structure, cutting that false positive.
        seq = self._sequence_similarity(left, right)
        jac = self._jaccard_similarity(left, right)
        return (seq * 0.6) + (jac * 0.4)

    def _sequence_similarity(self, left, right):
        left_norm = self._normalize_text(left)[: self.SIMILARITY_SAMPLE_CHARS]
        right_norm = self._normalize_text(right)[: self.SIMILARITY_SAMPLE_CHARS]
        if not left_norm or not right_norm:
            return 0.0
        try:
            return difflib.SequenceMatcher(None, left_norm, right_norm).ratio()
        except Exception:
            return 0.0

    def _jaccard_similarity(self, left, right):
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

    def _bodies_equivalent(self, response_a, response_b):
        try:
            info_a = self._helpers.analyzeResponse(response_a)
            info_b = self._helpers.analyzeResponse(response_b)
            body_a = self._body_text(response_a, info_a)
            body_b = self._body_text(response_b, info_b)
            return self._sequence_similarity(body_a, body_b) >= 0.95
        except Exception:
            return False

    # ------------------------------------------------------------------ CDN detection
    def _cdn_signal(self, response):
        # Returns ("strong"|"weak"|"", marker). "strong" => CDN-specific; "weak" => a cache/
        # proxy header a plain origin can also emit (used for annotation only).
        if not response:
            return ("", "")
        try:
            headers = self._helpers.analyzeResponse(response).getHeaders()
        except Exception:
            return ("", "")
        weak_hit = ""
        for header in headers:
            lower = header.lower()
            name = header.split(":", 1)[0]
            for marker in self.CDN_STRONG_HEADERS:
                if lower.startswith(marker) or ((":" not in marker) and marker in lower):
                    return ("strong", name)
            if lower.startswith("server:"):
                value = lower.split(":", 1)[1].strip()
                for marker in self.CDN_STRONG_SERVER:
                    if marker in value:
                        return ("strong", "Server:" + marker)
                for marker in self.CDN_WEAK_SERVER:
                    if marker in value and not weak_hit:
                        weak_hit = "Server:" + marker
            if lower.startswith("via:"):
                value = lower.split(":", 1)[1]
                for marker in self.CDN_STRONG_VIA:
                    if marker in value:
                        return ("strong", "Via:" + marker)
                for marker in self.CDN_WEAK_VIA:
                    if marker in value and not weak_hit:
                        weak_hit = "Via:" + marker
            if not weak_hit:
                for marker in self.CDN_WEAK_HEADERS:
                    if lower.startswith(marker):
                        weak_hit = name
                        break
        return ("weak", weak_hit) if weak_hit else ("", "")

    def _parse_cidrs(self, cidrs):
        networks = []
        for cidr in cidrs:
            try:
                net, bits = cidr.split("/")
                base = struct.unpack("!I", socket.inet_aton(net))[0]
                bits = int(bits)
                mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
                networks.append((base & mask, mask))
            except Exception:
                continue
        return networks

    def _ip_in_cdn_range(self, ip):
        try:
            value = struct.unpack("!I", socket.inet_aton(ip))[0]
        except Exception:
            return (False, "")   # not IPv4 (e.g. IPv6) -- range check not applied
        for base, mask in getattr(self, "_cdn_networks", []):
            if (value & mask) == base:
                return (True, "cdn-ip-range")
        return (False, "")

    # ------------------------------------------------------------------ DNS
    def _resolve_candidate_ips(self, host):
        candidates = []
        for label in self._candidate_labels(host):
            if self._shutdown.is_set():
                break
            try:
                infos = socket.getaddrinfo(label, None)
                for info in infos:
                    address = info[4][0]
                    if self._is_ip(address) and address not in candidates:
                        candidates.append(address)
                        if len(candidates) >= self.MAX_CANDIDATE_IPS:
                            break
            except socket.gaierror:
                continue
            except Exception as exc:
                self._log("Resolution error for %s: %s" % (label, exc))
            if len(candidates) >= self.MAX_CANDIDATE_IPS:
                break
        if candidates:
            self._log("Resolved %s -> %s" % (host, ", ".join(candidates)))
        else:
            self._log("Resolved %s -> none" % host)
        return candidates

    # ------------------------------------------------------------------ helpers
    def _is_https_sample(self, sample):
        try:
            return str(sample["item"].getHttpService().getProtocol()).lower() == "https"
        except Exception:
            return False

    def _trim_bytes(self, data):
        try:
            if data is not None and len(data) > self.MAX_BODY_BYTES:
                return data[: self.MAX_BODY_BYTES]
        except Exception:
            pass
        return data

    def _is_analyzable_response(self, response):
        try:
            info = self._helpers.analyzeResponse(response)
            content_type = self._content_type_family(
                self._get_header_value(info.getHeaders(), "Content-Type")
            )
        except Exception:
            return True   # if we cannot tell, do not drop it
        if not content_type:
            return True
        for skip in self.SKIP_TYPES:
            if content_type.startswith(skip):
                return False
        for ok in self.ANALYZABLE_TYPES:
            if content_type.startswith(ok):
                return True
        return False

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

    def _looks_like_direct_ip_block(self, status, body_text, title_text, location):
        combined = " ".join([title_text or "", body_text[:2000] or "", location or ""]).lower()
        markers = [
            "direct ip access", "ip access not allowed", "request blocked", "access denied",
            "forbidden", "not allowed", "unknown host", "default backend", "default virtual host",
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
        return self._normalize_location(original_location, host) == self._normalize_location(probe_location, host)

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

    def _html_escape(self, value):
        value = str(value or "")
        return (value.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    def _dialog_parent(self):
        # Parent the dialog on the UI's own window ancestor -- no fragile Burp-frame discovery.
        try:
            return SwingUtilities.getWindowAncestor(self._ui)
        except Exception:
            return self._ui

    def _mark_host_eval_complete(self, host):
        next_host = None
        with self._state_lock:
            if host in self._evaluating_hosts:
                self._evaluating_hosts.remove(host)
            if self._active_evals > 0:
                self._active_evals -= 1
            if self._pending_hosts and not self._shutdown.is_set():
                next_host = self._pending_hosts.pop(0)
                self._active_evals += 1
        if next_host:
            self._run_in_background("origin-eval-" + next_host, self._HostEvaluator(self, next_host))

    def _clear_state(self):
        with self._state_lock:
            self._host_samples = {}
            self._host_rows = {}
            self._host_verdict = {}
            self._host_evidence = {}
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

    # ------------------------------------------------------------------ table snapshot (thread-safe)
    def _iter_visible_rows(self):
        # Take a consistent snapshot of ALL shared state under the lock (rows + the scope
        # decision for each host), then filter without touching shared collections again.
        scope_only = self._scope_only_checkbox.isSelected()
        with self._state_lock:
            hosts = sorted(self._host_rows.keys())
            snapshot = []
            for host in hosts:
                in_scope = self._samples_in_scope(self._host_samples.get(host, [])) if scope_only else True
                snapshot.append((host, list(self._host_rows[host]), in_scope))

        visible = []
        likely_only = self._likely_only_checkbox.isSelected()
        suppress_low_signal = self._suppress_low_signal_checkbox.isSelected()
        for host, row, in_scope in snapshot:
            if scope_only and not in_scope:
                continue
            if likely_only and not self._result_is_likely(row[6]):
                continue
            if (suppress_low_signal and self._is_low_signal_host(host)
                    and row[6] in ["INCONCLUSIVE", "POSSIBLE_ORIGIN"]):
                continue
            visible.append((host, row))
        return visible

    def _samples_in_scope(self, samples):
        for sample in samples:
            if self._callbacks.isInScope(sample["url"]):
                return True
        return False

    def _refresh_table(self, _event):
        # Compute the visible snapshot OFF the EDT, then apply a MINIMAL in-place update on
        # the EDT: resize the row count once and write only cells that actually changed.
        # This avoids the full clear+repopulate churn and preserves column widths/selection.
        visible = self._iter_visible_rows()
        column_count = len(self._columns)

        class TableRefresher(Runnable):
            def __init__(self, extender, rows):
                self._extender = extender
                self._rows = rows

            def run(self):
                model = self._extender._table_model
                model.setRowCount(len(self._rows))
                index = {}
                for position in range(len(self._rows)):
                    host, row = self._rows[position]
                    index[host] = position
                    for column in range(column_count):
                        value = row[column] if column < len(row) else ""
                        try:
                            current = model.getValueAt(position, column)
                        except Exception:
                            current = None
                        if current != value:
                            model.setValueAt(value, position, column)
                self._extender._visible_rows = index

        SwingUtilities.invokeLater(TableRefresher(self, visible))

    def _on_filter_changed(self, _event):
        self._refresh_table(None)
        self._log(
            "Filters updated: only_in_scope=%s only_likely_origin=%s suppress_low_signal=%s active_probing=%s"
            % ("on" if self._scope_only_checkbox.isSelected() else "off",
               "on" if self._likely_only_checkbox.isSelected() else "off",
               "on" if self._suppress_low_signal_checkbox.isSelected() else "off",
               "on" if self._active_probe_checkbox.isSelected() else "off")
        )

    def _log(self, message):
        class LogAppender(Runnable):
            def __init__(self, extender, text):
                self._extender = extender
                self._text = text

            def run(self):
                self._extender._log_area.append("[*] " + self._text + "\n")

        try:
            SwingUtilities.invokeLater(LogAppender(self, message))
        except Exception:
            pass
        try:
            print("[OriginIpAutoDetect] %s" % message)
        except Exception:
            pass

    def _report_error(self, context, exc):
        message = "%s: %s" % (context, exc)
        try:
            self._callbacks.printError(message)
        except Exception:
            pass
        self._log("ERROR: " + message)

    def _run_in_background(self, name, runnable):
        if self._shutdown.is_set():
            return None
        worker = Thread(runnable, name)
        worker.setDaemon(True)
        with self._workers_lock:
            self._workers = [t for t in self._workers if self._is_alive(t)]
            self._workers.append(worker)
        worker.start()
        return worker

    def _is_alive(self, thread):
        try:
            return thread.isAlive()
        except Exception:
            return False

    # ------------------------------------------------------------------ workers (each guarded)
    class _HistoryImporter(Runnable):
        def __init__(self, extender, force=False, reset_run_stats=False):
            self._extender = extender
            self._force = force
            self._reset_run_stats = reset_run_stats

        def run(self):
            try:
                self._extender._import_proxy_history(self._force, self._reset_run_stats)
            except Exception as exc:
                self._extender._report_error("history importer failed", exc)

    class _SiteMapImporter(Runnable):
        def __init__(self, extender, prefixes):
            self._extender = extender
            self._prefixes = prefixes

        def run(self):
            try:
                self._extender._do_import_site_map(self._prefixes)
            except Exception as exc:
                self._extender._report_error("site map importer failed", exc)

    class _MessageImporter(Runnable):
        def __init__(self, extender, messages, source_label):
            self._extender = extender
            self._messages = messages
            self._source_label = source_label

        def run(self):
            try:
                self._extender._import_messages(self._messages, self._source_label)
            except Exception as exc:
                self._extender._report_error("message importer failed", exc)

    class _MessageProcessor(Runnable):
        def __init__(self, extender, item, from_history, source_label):
            self._extender = extender
            self._item = item
            self._from_history = from_history
            self._source_label = source_label

        def run(self):
            try:
                self._extender._process_item(self._item, self._from_history, self._source_label)
            except Exception as exc:
                self._extender._report_error("message processor failed", exc)

    class _HostEvaluator(Runnable):
        def __init__(self, extender, host):
            self._extender = extender
            self._host = host

        def run(self):
            try:
                self._extender._evaluate_host(self._host)
            except Exception as exc:
                self._extender._report_error("host evaluator failed for %s" % self._host, exc)


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity, confidence,
                 background, remediation):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence
        self._background = background
        self._remediation = remediation

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x08000000  # extension-generated

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueBackground(self):
        return self._background

    def getRemediationBackground(self):
        return self._remediation

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service


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
        elif result == "PROBABLE_ORIGIN":
            component.setBackground(Color(244, 81, 30))
            component.setForeground(Color.WHITE)
        elif result == "LIKELY_ORIGIN":
            component.setBackground(Color(251, 140, 0))
            component.setForeground(Color.WHITE)
        elif result == "RESPONDS_VIA_CDN":
            component.setBackground(Color(66, 133, 244))
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
