"""SysHealth command-line interface. Run `python cli.py --help` or `python cli.py cheatsheet`."""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import threading

from core import (app_updates, changes, cheatsheet, cleanup, connections, disk_health, events, long_paths,
                  netperf, network, persistence, security, settings, shredder, state, system_health, virustotal)
from core.checks import FAIL, WARN, execute_fix
from core.disk_usage import analyze as analyze_space
from core.duplicates import find_duplicates, index_files
from core.malware import Allowlist, ClamAV, Defender, quick_scan_locations, scan_unknown_files
from core.platform_utils import IS_LINUX, IS_WINDOWS, Cancelled, NeedsAdmin, human_size
from core.quarantine import Quarantine

EXIT_OK, EXIT_FOUND, EXIT_ADMIN = 0, 1, 2
CANCEL = threading.Event()


# =============================================================================== output helpers
class Out:
    json_mode = False

    @classmethod
    def log(cls, msg: str) -> None:
        if not cls.json_mode:
            print(msg, flush=True)

    @classmethod
    def quiet(cls, msg: str) -> None:  # progress lines go to stderr so stdout stays clean
        if not cls.json_mode:
            print(msg, file=sys.stderr, flush=True)


def to_jsonable(obj):
    if dataclasses.is_dataclass(obj):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return obj


def emit(data, table_rows=None, headers=None, title: str = "") -> None:
    if Out.json_mode:
        print(json.dumps(to_jsonable(data), indent=2, ensure_ascii=False, default=str))
        return
    if title:
        print(title)
    if table_rows is not None:
        print_table(headers or [], table_rows)


def print_table(headers: list[str], rows: list[list]) -> None:
    rows = [[str(c) for c in r] for r in rows]
    if not rows:
        print("  (none)")
        return
    widths = [min(max(len(h), *(len(r[i]) for r in rows)), 70) for i, h in enumerate(headers)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print(fmt.format(*["-" * w for w in widths]))
    for r in rows:
        print(fmt.format(*[c if len(c) <= w else c[:w - 1] + "…" for c, w in zip(r, widths)]))


def confirm(args, question: str) -> bool:
    if getattr(args, "yes", False):
        return True
    if Out.json_mode or not sys.stdin.isatty():
        print("Refusing to make changes without --yes in non-interactive mode.", file=sys.stderr)
        return False
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


# =============================================================================== commands
def cmd_cheatsheet(args) -> int:
    if Out.json_mode:
        emit([{"section": s, "command": c, "description": d} for s, c, d in cheatsheet.rows()])
    else:
        print(cheatsheet.as_text())
    return EXIT_OK


def cmd_check(args) -> int:
    modules = {"network": network, "system": system_health, "disk": disk_health, "security": security}
    names = list(modules) if args.area == "all" else [args.area]
    result, worst = {}, EXIT_OK
    for name in names:
        checks = modules[name].run_checks(Out.quiet)
        result[name] = checks
        fails = [c for c in checks if c.status == FAIL]
        warns = [c for c in checks if c.status == WARN]
        level = "FAIL" if fails else ("WARN" if warns else "OK")
        value = f"{len(fails)} problem(s)" if fails else (f"{len(warns)} warning(s)" if warns else "Healthy")
        if name == "security":
            value = f"Score {security.score(checks)}/100"
        state.publish(name, level, value, ", ".join(c.name for c in (fails + warns)[:3]))
        if fails or warns:
            worst = EXIT_FOUND
        if not Out.json_mode:
            print(f"\n== {name.upper()} ==")
            print_table(["Status", "Check", "Details", "Fix"],
                        [[c.status, c.name, c.detail, c.fix_id or ""] for c in checks])
    emit(result) if Out.json_mode else None
    return worst


def cmd_large(args) -> int:
    rep = analyze_space(args.paths, args.top, CANCEL, Out.quiet)
    folders = rep.top_folders(args.top)
    data = {"total_size": rep.total_size, "total_files": rep.total_files,
            "largest_files": [{"path": f.path, "size": f.size} for f in rep.largest[:args.top]],
            "largest_folders": [{"path": p, "size": s} for p, s in folders]}
    state.publish("largefiles", "INFO", human_size(rep.total_size), f"{rep.total_files:,} files measured")
    if Out.json_mode:
        emit(data)
    else:
        print(f"Measured {rep.total_files:,} files, {human_size(rep.total_size)}.\n\nLARGEST FOLDERS")
        print_table(["Size", "Folder"], [[human_size(s), p] for p, s in folders])
        print("\nLARGEST FILES")
        print_table(["Size", "File"], [[human_size(f.size), f.path] for f in rep.largest[:args.top]])
    return EXIT_OK


def cmd_duplicates(args) -> int:
    mode = "name" if args.by == "name" else "size_ext"
    files = index_files(args.paths, max(1, args.min_kb * 1024), cancel=CANCEL, progress=Out.quiet,
                        include_program=args.include_program)
    groups = find_duplicates(files, mode, not args.no_verify, CANCEL, Out.quiet)
    if args.export:
        from core.duplicates import export_xlsx
        rows = export_xlsx(groups, args.export, args.paths, mode, not args.no_verify)
        Out.quiet(f"Excel report saved: {args.export} ({rows:,} files).")
    wasted = sum(g.wasted for g in groups)
    state.publish("duplicates", "WARN" if wasted > 1024 ** 3 else ("INFO" if groups else "OK"),
                  f"{human_size(wasted)} reclaimable" if groups else "No duplicates", f"{len(groups)} groups")
    if Out.json_mode:
        emit(groups)
    else:
        for i, g in enumerate(groups, 1):
            print(f"\nGroup {i}: {g.label} — {len(g.files)} files, reclaim {human_size(g.wasted)}")
            for f in g.files:
                print(f"   {human_size(f.size):>9}  {f.path}")
        print(f"\n{len(groups)} groups, {human_size(wasted)} reclaimable.")
    return EXIT_FOUND if groups else EXIT_OK


def cmd_longpaths(args) -> int:
    if args.undo:
        n, errors = long_paths.undo_last(Out.log)
        Out.log(f"Restored {n} name(s).")
        return EXIT_FOUND if errors else EXIT_OK
    items, checked = long_paths.scan(args.paths, args.limit, CANCEL, Out.quiet)
    proposals, unresolved = long_paths.plan(items, args.limit, args.max_name)
    files = sum(1 for i in items if not i.is_dir)
    state.publish("longpaths", "WARN" if items else "OK", f"{files} long path(s)" if items else "No long paths",
                  f"Limit {args.limit}")
    emit({"long_items": items, "proposals": [dict(path=p.path, new_name=p.new_name, saves=p.saves,
                                                  files=p.affected) for p in proposals],
          "unresolved": unresolved},
         [[p.old_name, p.new_name, p.saves, p.affected] for p in proposals],
         ["Current name", "Proposed name", "Saves", "Files"],
         f"{files} file(s) exceed {args.limit} characters; {len(proposals)} rename(s) proposed.")
    if args.fix and proposals and confirm(args, f"Rename {len(proposals)} item(s)?"):
        done, errors = long_paths.apply(proposals, Out.log, CANCEL)
        state.record_action("Long paths", f"Renamed {len(done)} item(s)", f"limit {args.limit}")
        for e in errors:
            Out.log(f"Failed: {e}")
    return EXIT_FOUND if items else EXIT_OK


def cmd_malware(args) -> int:
    targets = args.paths or quick_scan_locations()
    engines = set((args.engines or "clamav,defender,unknown").split(","))
    clam, defender, results = ClamAV(), Defender(), []
    if "clamav" in engines:
        if clam.installed():
            results += clam.scan(targets, Out.quiet, CANCEL)
        else:
            Out.quiet("ClamAV is not installed (run: clamav install). Skipping.")
    if "defender" in engines and IS_WINDOWS and defender.installed():
        results += defender.scan(targets, Out.quiet, CANCEL)
    if "unknown" in engines:
        results += scan_unknown_files(Out.quiet, CANCEL, Allowlist(), None if not args.paths else targets)
    threats = [r for r in results if r.source != "Heuristic"]
    state.publish("malware", "FAIL" if threats else ("WARN" if results else "OK"),
                  f"{len(threats)} threat(s)" if threats else (f"{len(results)} to review" if results else "No threats"))
    emit(results, [[r.source, r.name, human_size(r.size), r.path] for r in results],
         ["Engine", "Detection", "Size", "Path"], f"{len(threats)} threat(s), {len(results) - len(threats)} unknown.")
    return EXIT_FOUND if results else EXIT_OK


def cmd_signatures(args) -> int:
    clam, defender = ClamAV(), Defender()
    failed = []
    if clam.installed():
        if clam.update(Out.log, CANCEL) not in (0, 1):
            failed.append("ClamAV")
        Out.log(f"ClamAV: {clam.db_status()}")
    else:
        Out.log("ClamAV is not installed (run: clamav install).")
    if IS_WINDOWS and defender.installed():
        if defender.update(Out.log, CANCEL) not in (0, None):
            failed.append("Microsoft Defender")
    if failed:
        print(f"Signature update failed for: {', '.join(failed)}", file=sys.stderr)
        state.record_action("Malware", "Signature update failed", ", ".join(failed))
        return EXIT_FOUND
    state.record_action("Malware", "Updated malware signatures", f"ClamAV: {clam.db_status()}")
    return EXIT_OK


def cmd_linux_tools(args) -> int:
    from core import linux_tools
    if not IS_LINUX:
        Out.log("Helper tools are only needed on Linux.")
        return EXIT_OK
    needed = linux_tools.missing()
    if args.action == "check" or not needed:
        emit([t.__dict__ for t in needed], [[t.package, t.purpose] for t in needed], ["Missing package", "Used for"],
             "All helper tools are installed." if not needed else "Missing helper tools:")
        return EXIT_FOUND if needed and args.action == "check" else EXIT_OK
    linux_tools.install(needed, Out.log, CANCEL)
    state.record_action("System", "Installed helper tools", ", ".join(t.package for t in needed))
    Out.log("Helper tools installed.")
    return EXIT_OK


def cmd_clamav(args) -> int:
    ClamAV().install(Out.log, CANCEL)
    state.record_action("Malware", "Installed ClamAV")
    return EXIT_OK


def cmd_cleanup(args) -> int:
    cats = {c.id: c for c in cleanup.categories()}
    if args.action == "analyze":
        rows, data, total = [], [], 0
        for c in cats.values():
            size, count = cleanup.analyze(c, CANCEL)
            total += size
            rows.append([c.id, c.title, human_size(size), count, "yes" if c.admin else ""])
            data.append({"id": c.id, "title": c.title, "size": size, "files": count, "admin": c.admin})
        state.publish("cleanup", "WARN" if total > 2 * 1024 ** 3 else "INFO", f"{human_size(total)} reclaimable")
        emit(data, rows, ["ID", "Category", "Size", "Files", "Admin"], f"Total reclaimable: {human_size(total)}")
        return EXIT_OK
    if args.action == "run":
        unknown = [i for i in args.ids if i not in cats]
        if unknown or not args.ids:
            print(f"Unknown or missing category. Valid IDs: {', '.join(cats)}", file=sys.stderr)
            return EXIT_FOUND
        if not confirm(args, f"Clean {', '.join(args.ids)}?"):
            return EXIT_OK
        freed = 0
        for i in args.ids:
            f, n = cleanup.clean(cats[i], Out.log, CANCEL)
            freed += f
        state.record_action("Cleanup", f"Freed {human_size(freed)}", ", ".join(args.ids))
        return EXIT_OK
    if args.action == "old-downloads":
        folder = args.ids[0] if args.ids else cleanup.downloads_folder()
        files = cleanup.old_files(folder, args.days, CANCEL)
        emit([{"path": p, "size": s} for p, s, _ in files], [[human_size(s), p] for p, s, _ in files],
             ["Size", "File"], f"{len(files)} file(s) in {folder} unused for {args.days}+ days, "
                               f"{human_size(sum(s for _, s, _ in files))}.")
        return EXIT_FOUND if files else EXIT_OK
    if args.action == "empty":
        dirs = cleanup.empty_folders(args.ids or [os.path.expanduser("~")], CANCEL)
        emit(dirs, [[d] for d in dirs], ["Empty folder"])
        if args.delete and dirs and confirm(args, f"Delete {len(dirs)} empty folder(s)?"):
            n, _ = cleanup.remove_empty_folders(dirs, Out.log)
            state.record_action("Cleanup", f"Removed {n} empty folder(s)")
        return EXIT_FOUND if dirs else EXIT_OK
    return EXIT_OK


def cmd_optimize(args) -> int:
    fixes = disk_health.get_fixes()
    key = f"optimize:{args.drive.rstrip(':').upper()}" if IS_WINDOWS else "trim"
    if key not in fixes:
        print(f"No optimize action for '{args.drive}'. Available: "
              f"{', '.join(k for k in fixes if k.startswith(('optimize', 'trim')))}", file=sys.stderr)
        return EXIT_FOUND
    execute_fix(fixes[key], Out.log, CANCEL)
    state.record_action("Disk", fixes[key].title)
    return EXIT_OK


def _autoruns(args, startup_only: bool) -> int:
    entries = persistence.collect(persistence.STARTUP_CATEGORIES if startup_only else None, True, Out.quiet, CANCEL)
    if getattr(args, "hide_microsoft", False):
        entries = [e for e in entries if not persistence.is_microsoft(e)]
    if getattr(args, "flagged_only", False):
        entries = [e for e in entries if e.flags]
    if not startup_only:
        added, removed, prev = persistence.diff_with_snapshot(entries)
        if added and not Out.json_mode:
            print(f"New since last scan ({prev}): " + ", ".join(a["name"] for a in added))
    rows = [[e.category, e.name, "on" if e.enabled else "off", e.risk, e.signer or e.sig_status,
             ", ".join(e.flags), e.command] for e in entries]
    emit([persistence.to_dict(e) for e in entries], rows,
         ["Type", "Name", "State", "Risk", "Publisher", "Flags", "Command"])
    return EXIT_FOUND if any(e.flags for e in entries) else EXIT_OK


def cmd_startup(args) -> int:
    return _autoruns(args, True)


def cmd_autoruns(args) -> int:
    return _autoruns(args, False)


def cmd_connections(args) -> int:
    conns = connections.list_connections()
    if args.listening:
        conns = [c for c in conns if c.is_listening]
    if args.internet:
        conns = [c for c in conns if "Internet" in c.flags]
    emit(conns, [[c.proto, c.process, c.pid, c.local, c.remote, c.status, ", ".join(c.flags)] for c in conns],
         ["Proto", "Process", "PID", "Local", "Remote", "State", "Flags"])
    return EXIT_OK


def cmd_events(args) -> int:
    groups = events.summarize(args.days)
    level, value, detail = events.headline(groups)
    state.publish("events", level, value, detail)
    emit(groups, [[g.severity, g.count, g.last, g.source, g.event_id, g.explanation or g.message[:90]]
                  for g in groups], ["Severity", "Count", "Last", "Source", "ID", "Meaning"])
    return EXIT_FOUND if level != "OK" else EXIT_OK


def cmd_changes(args) -> int:
    items = changes.collect(args.days, Out.quiet, CANCEL)
    state.publish("changes", "INFO", f"{len(items)} change(s)", f"last {args.days} days")
    emit(items, [[c.when, c.category, c.title, c.detail] for c in items], ["When", "Category", "Change", "Detail"])
    return EXIT_OK


def cmd_updates(args) -> int:
    items = app_updates.list_updates(Out.quiet)
    if args.action == "list":
        state.publish("updates", "WARN" if items else "OK", f"{len(items)} update(s)" if items else "Up to date")
        emit(items, [[i.name, i.id, i.current, i.available, i.source] for i in items],
             ["Name", "ID", "Current", "Available", "Source"])
        return EXIT_FOUND if items else EXIT_OK
    if args.all:
        if confirm(args, f"Update all {len(items)} app(s)?"):
            app_updates.install_all(Out.log, CANCEL)
            state.record_action("Updates", f"Updated all apps ({len(items)})")
        return EXIT_OK
    chosen = [i for i in items if i.id in args.ids]
    if not chosen:
        print("None of the given IDs has an update. Run 'updates list' to see IDs.", file=sys.stderr)
        return EXIT_FOUND
    if confirm(args, f"Update {', '.join(i.name for i in chosen)}?"):
        ok, failed = app_updates.install(chosen, Out.log, CANCEL)
        state.record_action("Updates", f"Updated {ok} app(s)", ", ".join(i.name for i in chosen))
        return EXIT_FOUND if failed else EXIT_OK
    return EXIT_OK


PROVIDER_ALIASES = {"cloudflare": "Cloudflare", "google": "Google", "quad9": "Quad9 (blocks malware)",
                    "opendns": "OpenDNS", "family": "Cloudflare Family (blocks malware and adult)", "auto": None}


def cmd_dns(args) -> int:
    if args.action == "test":
        res = netperf.benchmark(Out.quiet, CANCEL)
        emit(res, [[r["provider"], ", ".join(r["servers"]),
                    f"{r['median_ms']:.0f} ms" if r["median_ms"] is not None else "no response", r["failures"]]
                   for r in res], ["Provider", "Servers", "Median", "Failures"])
        return EXIT_OK
    if args.provider not in PROVIDER_ALIASES:
        print(f"Unknown provider. Choose from: {', '.join(PROVIDER_ALIASES)}", file=sys.stderr)
        return EXIT_FOUND
    fix = netperf.set_dns_fix(PROVIDER_ALIASES[args.provider])
    if confirm(args, f"{fix.title}?"):
        execute_fix(fix, Out.log, CANCEL)
        state.record_action("Network", fix.title)
    return EXIT_OK


def cmd_speedtest(args) -> int:
    r = netperf.speed_test(Out.quiet, CANCEL)
    state.publish("speedtest", "INFO", f"{r['download_mbps']} / {r['upload_mbps']} Mbps", f"ping {r['ping_ms']} ms",
                  r)
    emit(r, [[r["ping_ms"], r["jitter_ms"], r["download_mbps"], r["upload_mbps"]]],
         ["Ping ms", "Jitter ms", "Download Mbps", "Upload Mbps"])
    return EXIT_OK


def cmd_vt(args) -> int:
    target = args.target
    sha = virustotal.sha256_file(target) if os.path.isfile(target) else target
    r = virustotal.lookup(sha, settings.get("vt_api_key", ""))
    emit({**dataclasses.asdict(r), "verdict": r.verdict, "link": r.link},
         [[r.verdict, f"{r.malicious}/{r.total}" if r.found else "-", r.name, r.link]],
         ["Verdict", "Detections", "Name", "Report"])
    return EXIT_FOUND if r.verdict in ("Malicious", "Suspicious") else EXIT_OK


def cmd_selfupdate(args) -> int:
    from core import self_update
    from core.version import VERSION
    try:
        release = self_update.check(VERSION)
    except self_update.UpdateError as exc:
        print(f"Could not check for updates: {exc}", file=sys.stderr)
        return EXIT_FOUND
    if release is None:
        emit({"current": VERSION, "update_available": False})
        Out.log(f"SysHealth {VERSION} is the latest version.")
        return EXIT_OK
    emit({"current": VERSION, "update_available": True, "latest": release.version,
          "published": release.published, "summary": release.summary, "page": release.page})
    if not Out.json_mode:
        print(f"SysHealth {release.version} is available (you have {VERSION}). Released {release.published}.")
        print("\nWhat's new:")
        for line in release.summary:
            print(f"  {line}")
        print(f"\nFull release notes and downloads: {release.page}")
        print("To install it, open the SysHealth app and choose Update now, or download it from the page above.")
    return EXIT_FOUND


def cmd_config(args) -> int:
    keys = {"vt-key": "vt_api_key", "update-repo": "update_repo", "update-startup": "update_check_startup"}
    if args.action == "show":
        data = settings.load()
        if "vt_api_key" in data and data["vt_api_key"]:
            data["vt_api_key"] = data["vt_api_key"][:4] + "…"
        emit(data, [[k, v] for k, v in data.items()], ["Setting", "Value"])
        return EXIT_OK
    if args.key not in keys:
        print(f"Unknown setting. Available: {', '.join(keys)}", file=sys.stderr)
        return EXIT_FOUND
    value = args.value or ""
    if args.key == "update-startup":
        value = value.lower() in ("on", "yes", "true", "1")
    settings.set_value(keys[args.key], value)
    Out.log(f"Saved {args.key}.")
    return EXIT_OK


def cmd_shred(args) -> int:
    for p in args.paths:
        reason = shredder.check_allowed(p)
        if reason:
            print(f"Refusing: {p} {reason}.", file=sys.stderr)
            return EXIT_FOUND
    if not confirm(args, f"Permanently shred {len(args.paths)} item(s)? This cannot be undone."):
        return EXIT_OK
    n, size, errors = shredder.shred(args.paths, args.passes, Out.quiet, CANCEL)
    state.record_action("Shredder", f"Shredded {n} file(s)", human_size(size))
    Out.log(f"Shredded {n} file(s), {human_size(size)}.")
    for e in errors:
        Out.log(f"Failed: {e}")
    return EXIT_FOUND if errors else EXIT_OK


def cmd_quarantine(args) -> int:
    q = Quarantine()
    if args.action == "list":
        items = q.items()
        emit(items, [[i.id, i.date, i.reason, human_size(i.size), i.original_path] for i in items],
             ["ID", "Date", "Reason", "Size", "Original location"])
    elif args.action == "restore":
        Out.log(f"Restored to {q.restore(args.id)}")
    elif args.action == "purge":
        if confirm(args, "Permanently delete this quarantined file?"):
            q.purge(args.id)
    return EXIT_OK


def cmd_report(args) -> int:
    data = state.load()
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
        Out.log(f"Saved to {args.out}")
    if Out.json_mode:
        emit(data)
    else:
        print_table(["Area", "Status", "Result", "Updated"],
                    [[k, v.get("level"), v.get("value"), v.get("updated")] for k, v in data.items()
                     if isinstance(v, dict)])
        print(f"\nState file: {state.state_path()}")
    return EXIT_OK


# =============================================================================== parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=cheatsheet.CMD, description="SysHealth command line. "
                                "Run the 'cheatsheet' command for examples.")
    p.add_argument("--json", action="store_true", help="output JSON")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    def add(name, fn, help_text):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help=argparse.SUPPRESS)
        sp.set_defaults(fn=fn)
        return sp

    add("cheatsheet", cmd_cheatsheet, "print command examples")
    sp = add("check", cmd_check, "run health checks")
    sp.add_argument("area", choices=["all", "network", "system", "disk", "security"])
    sp = add("large", cmd_large, "largest files and folders")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--top", type=int, default=25)
    sp = add("duplicates", cmd_duplicates, "find duplicate files")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--by", choices=["size", "name"], default="size")
    sp.add_argument("--no-verify", action="store_true", help="skip content (hash) verification")
    sp.add_argument("--min-kb", type=int, default=100)
    sp.add_argument("--export", metavar="FILE.xlsx", help="save the results to an Excel workbook for review")
    sp.add_argument("--include-program", action="store_true",
                    help="also scan program and project folders (virtual environments, node_modules, .git...)")
    sp = add("longpaths", cmd_longpaths, "find and fix long paths")
    sp.add_argument("paths", nargs="*")
    sp.add_argument("--limit", type=int, default=218)
    sp.add_argument("--max-name", type=int, default=24)
    sp.add_argument("--fix", action="store_true")
    sp.add_argument("--undo", action="store_true", help="undo the last rename batch")
    sp.add_argument("--yes", action="store_true")
    sp = add("malware", cmd_malware, "scan for malware and unknown programs")
    sp.add_argument("paths", nargs="*")
    sp.add_argument("--quick", action="store_true", help="scan high-risk folders (default when no path given)")
    sp.add_argument("--engines", help="comma list: clamav,defender,unknown")
    sp = add("signatures", cmd_signatures, "update antivirus signatures")
    sp.add_argument("action", choices=["update"])
    sp = add("linux-tools", cmd_linux_tools, "Linux: check or install helper tools (clipboard, disk health)")
    sp.add_argument("action", choices=["check", "install"])
    sp = add("clamav", cmd_clamav, "install ClamAV")
    sp.add_argument("action", choices=["install"])
    sp = add("cleanup", cmd_cleanup, "temp files, caches, old downloads, empty folders")
    sp.add_argument("action", choices=["analyze", "run", "old-downloads", "empty"])
    sp.add_argument("ids", nargs="*", help="category IDs (run) or folders (old-downloads, empty)")
    sp.add_argument("--days", type=int, default=90)
    sp.add_argument("--delete", action="store_true")
    sp.add_argument("--yes", action="store_true")
    sp = add("optimize", cmd_optimize, "TRIM / defragment a drive")
    sp.add_argument("drive", nargs="?", default="C")
    sp = add("startup", cmd_startup, "list startup apps")
    sp.add_argument("--hide-microsoft", action="store_true")
    sp = add("autoruns", cmd_autoruns, "full autorun (persistence) audit")
    sp.add_argument("--hide-microsoft", action="store_true")
    sp.add_argument("--flagged-only", action="store_true")
    sp = add("connections", cmd_connections, "network connections by program")
    sp.add_argument("--listening", action="store_true")
    sp.add_argument("--internet", action="store_true")
    sp = add("events", cmd_events, "summarize event-log errors")
    sp.add_argument("--days", type=int, default=7)
    sp = add("changes", cmd_changes, "recent system and app changes")
    sp.add_argument("--days", type=int, default=7)
    sp = add("updates", cmd_updates, "list or install app updates")
    sp.add_argument("action", choices=["list", "install"])
    sp.add_argument("ids", nargs="*")
    sp.add_argument("--all", action="store_true")
    sp.add_argument("--yes", action="store_true")
    sp = add("dns", cmd_dns, "benchmark or switch DNS")
    sp.add_argument("action", choices=["test", "set"])
    sp.add_argument("provider", nargs="?", default="")
    sp.add_argument("--yes", action="store_true")
    add("speedtest", cmd_speedtest, "internet speed test")
    sp = add("vt", cmd_vt, "VirusTotal lookup of a file or SHA-256 hash")
    sp.add_argument("target")
    add("self-update", cmd_selfupdate, "check for a newer SysHealth and show what changed")
    sp = add("config", cmd_config, "show or set settings")
    sp.add_argument("action", choices=["show", "set"])
    sp.add_argument("key", nargs="?")
    sp.add_argument("value", nargs="?")
    sp = add("shred", cmd_shred, "securely delete files or folders")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--passes", type=int, default=1, choices=[1, 3, 7])
    sp.add_argument("--yes", action="store_true")
    sp = add("quarantine", cmd_quarantine, "manage quarantined files")
    sp.add_argument("action", choices=["list", "restore", "purge"])
    sp.add_argument("id", nargs="?")
    sp.add_argument("--yes", action="store_true")
    sp = add("report", cmd_report, "show or export the latest results")
    sp.add_argument("--out")
    return p


def main(argv=None) -> int:
    if IS_WINDOWS:
        try:
            sys.stdout.reconfigure(encoding="utf-8")
            sys.stderr.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    Out.json_mode = bool(args.json)
    if not getattr(args, "fn", None):
        parser.print_help()
        return EXIT_OK
    if args.command == "longpaths" and not args.paths and not args.undo:
        parser.error("longpaths needs at least one path (or --undo)")
    try:
        return args.fn(args)
    except NeedsAdmin as exc:
        print(f"'{exc}' requires administrator rights. "
              + ("Open the terminal with 'Run as administrator' and try again." if IS_WINDOWS
                 else "Run the command with sudo."), file=sys.stderr)
        return EXIT_ADMIN
    except (KeyboardInterrupt, Cancelled):
        CANCEL.set()
        print("\nCancelled.", file=sys.stderr)
        return EXIT_FOUND
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return EXIT_FOUND


if __name__ == "__main__":
    sys.exit(main())
