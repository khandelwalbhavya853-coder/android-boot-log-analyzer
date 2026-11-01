#!/usr/bin/env python3
"""Analyze Android dmesg/logcat text and produce a diagnostic report."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


UPTIME_RE = re.compile(r"^\[\s*(\d+(?:\.\d+)?)\]")
LOGCAT_RE = re.compile(
    r"^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+\d+\s+\d+\s+([VDIWEFA])\s+([^:]+):\s*(.*)$"
)
DATE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
DURATION_RE = re.compile(
    r"(?:init:\s*)?(?:processing action|service|\w[\w./-]*)[^\n]{0,100}?\b(?:took|duration[=:])\s*(\d+(?:\.\d+)?)\s*(ms|msec|milliseconds|s|sec|seconds)\b",
    re.IGNORECASE,
)

RULES = [
    ("SELinux", re.compile(r"avc:\s*denied|selinux.*(?:denied|denial)|audit\([^)]*\).*denied", re.I)),
    ("Firmware", re.compile(r"firmware.{0,50}(?:failed|missing|not found|error|timeout)|(?:failed|missing|not found).{0,50}firmware|Direct firmware load.*failed", re.I)),
    ("Driver", re.compile(r"(?:driver|probe).{0,60}(?:failed|failure|error|timeout)|(?:failed|failure|error|timeout).{0,60}(?:driver|probe)|deferred probe", re.I)),
    ("Kernel", re.compile(r"\b(kernel panic|oops:|BUG:|unable to handle kernel|call trace:|watchdog.*(?:bite|timeout))\b", re.I)),
    ("Init", re.compile(r"\b(init|init rc|service).{0,60}(?:failed|failure|error|timeout|crash)\b|\b(?:failed|failure|timeout).{0,60}\binit\b", re.I)),
    ("Framework", re.compile(r"system_server.*(?:crash|fatal|exception)|\bfatal exception\b|\bframework.*(?:failed|crash|error)\b", re.I)),
]

SEVERITY_PATTERNS = {
    "CRITICAL": re.compile(r"kernel panic|\bpanic\b|fatal exception|watchdog.*(?:bite|timeout)|\bBUG:\s*", re.I),
    "ERROR": re.compile(r"\berror\b|\bfailed\b|\bfailure\b|\bdenied\b|\btimeout\b|\boops:\b", re.I),
    "WARNING": re.compile(r"\bwarn(?:ing)?\b|\bdeferred probe\b|\bslow\b", re.I),
}
LOGCAT_SEVERITY = {"A": "CRITICAL", "F": "CRITICAL", "E": "ERROR", "W": "WARNING"}


@dataclass
class Issue:
    severity: str
    category: str
    message: str
    line_number: int
    timestamp: float | None = None


@dataclass
class SlowStage:
    name: str
    duration_ms: float
    line_number: int


def _timestamp(line: str, logcat_origin: int | None) -> float | None:
    match = UPTIME_RE.match(line)
    if match:
        return float(match.group(1))
    match = LOGCAT_RE.match(line)
    if match:
        # Logcat's MM-DD clock has no year; use seconds within the day. The
        # report uses the elapsed span, so this remains useful across midnight.
        from datetime import datetime
        try:
            dt = datetime.strptime(match.group(1), "%m-%d %H:%M:%S.%f")
            value = dt.timetuple().tm_yday * 86400 + dt.hour * 3600 + dt.minute * 60 + dt.second + dt.microsecond / 1e6
            return value
        except ValueError:
            return None
    match = DATE_RE.match(line)
    if match:
        from datetime import datetime
        try:
            dt = datetime.strptime(" ".join(match.groups()), "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            try:
                dt = datetime.strptime(" ".join(match.groups()), "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        return dt.timestamp()
    return None


def _category(text: str) -> str:
    for category, pattern in RULES:
        if pattern.search(text):
            return category
    return "General"


def _severity(text: str, logcat_priority: str | None) -> str | None:
    if logcat_priority in LOGCAT_SEVERITY:
        return LOGCAT_SEVERITY[logcat_priority]
    for severity, pattern in SEVERITY_PATTERNS.items():
        if pattern.search(text):
            return severity
    return None


def analyze_lines(lines: Iterable[str], slow_threshold_ms: float = 1000.0) -> dict:
    issues: list[Issue] = []
    stages: list[SlowStage] = []
    timed: list[float] = []
    seen: set[tuple[str, str]] = set()
    logcat_day_offset = 0.0
    last_logcat_time: float | None = None

    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        ts = _timestamp(line, None)
        if LOGCAT_RE.match(line) and ts is not None:
            if last_logcat_time is not None and ts < last_logcat_time - 12 * 3600:
                logcat_day_offset += 365 * 86400
            last_logcat_time = ts
            ts += logcat_day_offset
        if ts is not None:
            timed.append(ts)

        logcat = LOGCAT_RE.match(line)
        priority = logcat.group(2) if logcat else None
        message = f"{logcat.group(3)}: {logcat.group(4)}" if logcat else line.strip()
        severity = _severity(message, priority)
        if severity:
            key = (severity, message)
            if key not in seen:
                issues.append(Issue(severity, _category(message), message, line_number, ts))
                seen.add(key)

        duration_match = DURATION_RE.search(message)
        if duration_match:
            amount = float(duration_match.group(1))
            unit = duration_match.group(2).lower()
            duration_ms = amount * (1000 if unit in {"s", "sec", "seconds"} else 1)
            if duration_ms >= slow_threshold_ms:
                label = message[:160]
                stages.append(SlowStage(label, duration_ms, line_number))

    if timed:
        boot_time = max(timed) - min(timed)
    else:
        boot_time = None

    counts: dict[str, int] = {}
    for issue in issues:
        counts[issue.category] = counts.get(issue.category, 0) + 1
    recommendations = _recommendations(issues, stages)
    return {
        "title": "Android Boot Diagnostic Report",
        "total_boot_time_seconds": round(boot_time, 3) if boot_time is not None else None,
        "issue_count": len(issues),
        "issue_counts_by_category": dict(sorted(counts.items())),
        "issues": [asdict(issue) for issue in issues],
        "slow_stages": [asdict(stage) for stage in sorted(stages, key=lambda item: item.duration_ms, reverse=True)],
        "recommendations": recommendations,
        "notes": [] if timed else ["No recognized timestamps were found; boot time could not be calculated."],
    }


def _recommendations(issues: list[Issue], stages: list[SlowStage]) -> list[str]:
    categories = {issue.category for issue in issues}
    out: list[str] = []
    if "Kernel" in categories:
        out.append("Investigate the kernel panic, oops, or watchdog trace and check the matching kernel build.")
    if "Driver" in categories:
        out.append("Investigate driver probe or initialization failures, including device-tree and hardware configuration.")
    if "Firmware" in categories:
        out.append("Check that the required firmware file exists at the expected path and matches the driver and device.")
    if "SELinux" in categories:
        out.append("Review the SELinux denial context and add only the policy rule required for the intended access.")
    if "Init" in categories:
        out.append("Inspect the failing init service or action, its dependencies, and the relevant init .rc configuration.")
    if "Framework" in categories:
        out.append("Inspect system_server or framework crash details and the first fatal exception in the log.")
    if stages:
        out.append("Profile the slow initialization stages and check whether their work can start later or run in parallel.")
    if not out and issues:
        out.append("Review the flagged lines in context and correlate them with the device build and boot stage.")
    if not issues:
        out.append("No matching error or warning rules fired. Review the full log and add device-specific signatures if needed.")
    return out


def render_html(report: dict) -> str:
    boot_time = report["total_boot_time_seconds"]
    boot_label = f"{boot_time:g} seconds" if boot_time is not None else "Unavailable"
    summary_rows = "".join(
        f"<tr><th>{html.escape(category)}</th><td>{count}</td></tr>"
        for category, count in report["issue_counts_by_category"].items()
    ) or '<tr><td colspan="2">No issues detected</td></tr>'
    issue_rows = "".join(
        "<tr>"
        f"<td><span class=\"severity severity-{html.escape(issue['severity'].lower())}\">{html.escape(issue['severity'])}</span></td>"
        f"<td><span class=\"category-chip\">{html.escape(issue['category'])}</span></td>"
        f"<td>{issue['line_number']}</td><td class=\"message\">{html.escape(issue['message'])}</td>"
        "</tr>"
        for issue in report["issues"]
    ) or '<tr><td colspan="4">No issues detected</td></tr>'
    stages = "".join(f"<li><span class=\"list-icon\">◷</span><span><strong>{stage['duration_ms']:g} ms</strong> — {html.escape(stage['name'])} <span class=\"muted\">(line {stage['line_number']})</span></span></li>" for stage in report["slow_stages"])
    recs = "".join(f"<li><span class=\"list-icon sparkle\">✧</span><span>{html.escape(item)}</span></li>" for item in report["recommendations"])
    notes = "".join(f"<p class=\"note\">{html.escape(item)}</p>" for item in report["notes"])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(report['title'])}</title><style>
:root{{--ink:#f5f1ff;--muted:#b8b1ce;--line:rgba(190,166,255,.15);--purple:#9b7aff;--violet:#b09aff;--paper:#080610;--card:#100d1b}}
*{{box-sizing:border-box;scroll-behavior:smooth}}
body{{font:15px/1.6 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;max-width:1160px;margin:0 auto;padding:26px 26px 58px;color:var(--ink);background:radial-gradient(ellipse at 50% -10%,rgba(121,82,244,.66),rgba(85,56,178,.36) 18rem,transparent 42rem),radial-gradient(ellipse at 8% 18%,rgba(93,61,193,.21),transparent 29rem),radial-gradient(ellipse at 94% 25%,rgba(104,61,191,.17),transparent 27rem),var(--paper)}}
header,.card{{position:relative;background:var(--card);border:1px solid rgba(190,166,255,.13);border-radius:22px;padding:24px 28px;margin:19px 0;box-shadow:0 18px 50px rgba(0,0,0,.24)}}
.hero{{overflow:hidden;padding:20px 30px 54px;animation:rise .65s ease-out both;background:radial-gradient(ellipse at 50% -30%,rgba(164,132,255,.12),transparent 38rem),linear-gradient(180deg,rgba(17,13,31,.72),rgba(8,6,16,.42));border-color:rgba(183,157,255,.12);box-shadow:none}}
.hero:before{{content:"";position:absolute;inset:-160px 12% auto;height:360px;border-radius:50%;background:radial-gradient(ellipse,rgba(151,111,255,.50),rgba(119,82,228,.22) 38%,rgba(82,54,166,.08) 61%,transparent 74%);filter:blur(12px);pointer-events:none;animation:glow 6s ease-in-out infinite alternate}}
.hero:after{{content:"";position:absolute;inset:0;pointer-events:none;background-image:radial-gradient(#fff 0.7px,transparent .9px);background-size:73px 73px;opacity:.16;mask-image:linear-gradient(180deg,#000,transparent 80%)}}
.topbar{{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:18px;max-width:940px;margin:0 auto}}
.brand{{display:flex;align-items:center;gap:9px;color:#fff;text-decoration:none;font-weight:760;letter-spacing:-.025em;white-space:nowrap}}
.brand-mark{{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:50%;color:#fff;background:linear-gradient(140deg,#9a72f0,#6745cf);font-size:17px;box-shadow:0 5px 18px #805eea55}}
.nav-pill{{display:flex;align-items:center;gap:3px;padding:5px;border:1px solid rgba(197,177,255,.15);border-radius:999px;background:rgba(42,32,76,.76);backdrop-filter:blur(12px)}}.nav-pill a{{padding:6px 13px;border-radius:999px;color:#eee9ff;text-decoration:none;font-size:.83rem;transition:background .2s,color .2s,transform .2s}}.nav-pill a:hover{{background:rgba(154,118,255,.24);color:#fff;transform:translateY(-1px)}}
.ready{{display:flex;align-items:center;gap:7px;padding:7px 12px;border:1px solid rgba(191,170,255,.18);border-radius:999px;background:rgba(78,57,130,.48);color:#e7ddff;font-size:.78rem;font-weight:700;white-space:nowrap}}.ready-dot{{width:7px;height:7px;border-radius:50%;background:#8cf0c5;box-shadow:0 0 0 4px #45c28b20}}
.hero-copy{{position:relative;z-index:1;max-width:800px;margin:76px auto 0;text-align:center}}.eyebrow{{display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(190,166,255,.2);border-radius:999px;background:rgba(47,36,81,.42);color:#c6b2ff;font-size:.7rem;font-weight:760;letter-spacing:.13em}}
h1{{margin:22px 0 13px;color:#fff;font-size:clamp(2rem,5vw,3.45rem);line-height:1.12;letter-spacing:-.05em;text-shadow:0 5px 35px rgba(173,145,255,.2)}}.headline-accent{{display:block;color:#a98bff;text-shadow:0 8px 38px rgba(151,112,255,.55)}}
.hero-subtitle{{max-width:590px;margin:0 auto;color:#c1bad3;font-size:1rem}}.hero-metrics{{display:flex;justify-content:center;align-items:center;gap:10px;flex-wrap:wrap;margin-top:26px}}
.metric-count,.boot-value{{display:inline-flex;align-items:center;gap:8px;padding:8px 15px;border:1px solid rgba(192,168,255,.22);border-radius:999px;background:linear-gradient(135deg,#8d64f0,#6840cf);color:#fff;font-weight:720;box-shadow:0 8px 26px rgba(108,69,210,.28)}}.metric-count{{animation:softpulse 3.2s ease-in-out infinite}}.boot-value{{background:rgba(18,14,31,.62);border-color:rgba(226,216,255,.55);color:#f2edff;box-shadow:none}}.metric-symbol{{font-size:1.05rem}}
.card{{background:linear-gradient(135deg,rgba(19,15,31,.97),rgba(13,10,23,.98));border-color:rgba(177,151,255,.13);animation:rise .6s ease-out both;transition:transform .25s ease,box-shadow .25s ease}}.card:hover{{transform:translateY(-2px);box-shadow:0 20px 54px rgba(0,0,0,.34),0 0 30px rgba(116,82,208,.08)}}section.card:nth-of-type(2){{animation-delay:.08s}}section.card:nth-of-type(3){{animation-delay:.16s}}section.card:nth-of-type(4){{animation-delay:.24s}}section.card:nth-of-type(5){{animation-delay:.32s}}
h2{{display:flex;align-items:center;gap:10px;margin:0 0 16px;color:#f5f1ff;font-size:1.12rem;letter-spacing:-.015em}}.section-icon{{display:inline-grid;place-items:center;width:32px;height:32px;border-radius:11px;background:linear-gradient(145deg,#38275f,#251a42);color:#b8a0ff;font-size:17px}}
table{{border-collapse:separate;border-spacing:0;width:100%;overflow:hidden;background:#100d19;border:1px solid var(--line);border-radius:14px}}th,td{{border-bottom:1px solid rgba(196,177,255,.1);text-align:left;padding:12px 14px;vertical-align:top}}th{{color:#aaa1c2;font-size:.73rem;text-transform:uppercase;letter-spacing:.08em;background:#151120}}tbody tr:last-child td{{border-bottom:0}}tbody tr:hover{{background:#191426}}
.message{{overflow-wrap:anywhere;color:#ded8eb}}.severity,.category-chip{{display:inline-flex;align-items:center;padding:3px 9px;border-radius:999px;font-size:.73rem;font-weight:750;letter-spacing:.035em;white-space:nowrap}}.severity-critical{{color:#ff9eb6;background:rgba(155,45,80,.25)}}.severity-error{{color:#ffb18d;background:rgba(153,75,39,.24)}}.severity-warning{{color:#f6d583;background:rgba(145,111,34,.22)}}.category-chip{{color:#cfbdff;background:rgba(113,79,191,.24)}}
ul{{list-style:none;padding:0;margin:0;display:grid;gap:11px}}li{{display:flex;align-items:flex-start;gap:11px;padding:12px 14px;border:1px solid rgba(196,177,255,.11);border-radius:13px;background:linear-gradient(100deg,rgba(23,18,38,.96),rgba(17,13,29,.96));color:#e3deed}}.list-icon{{flex:0 0 25px;display:grid;place-items:center;width:25px;height:25px;border-radius:8px;background:rgba(52,132,143,.18);color:#75d9e1;font-size:16px}}.sparkle{{background:rgba(116,77,190,.2);color:#c2a8ff}}.muted,.note{{color:var(--muted)}}.note{{font-size:.9rem}}footer{{padding:8px 4px}}
@keyframes rise{{from{{opacity:0;transform:translateY(12px)}}to{{opacity:1;transform:translateY(0)}}}}@keyframes glow{{from{{transform:translateY(-7px) scale(.96);opacity:.65}}to{{transform:translateY(10px) scale(1.06);opacity:1}}}}@keyframes softpulse{{0%,100%{{box-shadow:0 5px 16px #7861ba0d}}50%{{box-shadow:0 5px 19px #9474ed2a}}}}
@media(max-width:720px){{body{{padding:14px 14px 36px}}header,.card{{padding:19px 16px;border-radius:18px}}.topbar{{flex-wrap:wrap;justify-content:center}}.nav-pill{{order:3;width:100%;justify-content:center;flex-wrap:wrap}}.nav-pill a{{padding:6px 10px}}.hero-copy{{margin-top:48px}}table{{font-size:.82rem}}th,td{{padding:9px 8px}}}}
@media(prefers-reduced-motion:reduce){{*,*::before,*::after{{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important;transition-duration:.01ms!important}}}}
</style></head><body><header class="hero"><div class="topbar"><a class="brand" href="#top"><span class="brand-mark">✦</span> BootLens</a><nav class="nav-pill" aria-label="Report sections"><a href="#summary">Overview</a><a href="#issues">Issues</a><a href="#stages">Startup stages</a><a href="#recommendations">Recommendations</a></nav><span class="ready"><span class="ready-dot"></span> Report ready</span></div>
<div class="hero-copy" id="top"><div class="eyebrow">◈ ANDROID BOOT / SYSTEM INSIGHTS</div><h1>See what’s happening at boot<span class="headline-accent">and where time is going.</span></h1>
<p class="hero-subtitle">A clear readout of errors, slow initialization, and suggested next steps from your Android boot log.</p>
<div class="hero-metrics"><span class="metric-count"><span class="metric-symbol">⌁</span> {report['issue_count']} issue(s) detected</span><span class="boot-value"><span class="metric-symbol">◷</span> {boot_label} boot span</span></div></div></header>
<section class="card" id="summary"><h2><span class="section-icon">⌘</span>Issue counts</h2><table>{summary_rows}</table></section>
<section class="card" id="issues"><h2><span class="section-icon">◉</span>Detected issues</h2><table><thead><tr><th>Severity</th><th>Category</th><th>Line</th><th>Message</th></tr></thead><tbody>{issue_rows}</tbody></table></section>
<section class="card" id="stages"><h2><span class="section-icon">◷</span>Slow initialization stages</h2><ul>{stages or '<li>No slow stages matched the configured threshold.</li>'}</ul></section>
<section class="card" id="recommendations"><h2><span class="section-icon">✧</span>Recommendations</h2><ul>{recs}</ul>{notes}</section>
<footer><p class="note">Automated heuristics can miss device-specific issues. Confirm findings against surrounding log lines and the exact device build.</p></footer>
</body></html>"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze Android dmesg or logcat boot logs.")
    parser.add_argument("log", type=Path, help="Input text log (dmesg or logcat)")
    parser.add_argument("--format", choices=("json", "html"), default="json", help="Report format (default: json)")
    parser.add_argument("--output", "-o", type=Path, help="Write report to this file; default is standard output")
    parser.add_argument("--slow-ms", type=float, default=1000.0, help="Slow-stage threshold in milliseconds (default: 1000)")
    args = parser.parse_args(argv)
    try:
        with args.log.open("r", encoding="utf-8", errors="replace") as source:
            report = analyze_lines(source, args.slow_ms)
    except OSError as exc:
        parser.error(str(exc))
    rendered = json.dumps(report, indent=2, ensure_ascii=False) if args.format == "json" else render_html(report)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
