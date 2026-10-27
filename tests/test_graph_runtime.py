"""Graph runtime: process lifecycle (runner) and lazy per-snapshot session."""

from __future__ import annotations

import _thread
import logging
import os
import sys
import shutil
import stat
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

from lgtm.config import LGTMConfig
from lgtm.graph import runner as runner_module
from lgtm.graph.runner import GraphOutcome, GraphRunner, remove_tree, sanitize_query
from lgtm.graph.session import GraphSession
from lgtm.graph.snapshot import resolve_refs
from lgtm.graph.exporter import export_snapshot

from tests.graph_fakes import (
    FLOOD_TOKEN,
    FakeCodegraph,
    FakeRunner,
    failure,
    kill_pids,
    make_fake_executable,
    no_match,
    success,
    wait_all_dead,
)

ALLOWED_ENV = {
    "PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG",
    "CODEGRAPH_NO_UPDATE_CHECK", "DO_NOT_TRACK", "CODEGRAPH_NO_DAEMON", "CODEGRAPH_NO_WATCH",
    "HOME", "USERPROFILE", "XDG_CONFIG_HOME",
}
PRIVATE_HOME_KEYS = ("HOME", "USERPROFILE", "XDG_CONFIG_HOME")


@pytest.fixture
def fake(tmp_path):
    exe = make_fake_executable(tmp_path / "bin", stdout="RESULT-TOKEN")
    yield exe
    kill_pids(exe.all_pids())


@pytest.fixture
def root(tmp_path) -> Path:
    path = tmp_path / "it's a root"
    path.mkdir()
    (path / "app.py").write_text("x = 1\n", encoding="utf-8")
    return path


def make_runner(exe, **kwargs) -> GraphRunner:
    limits = {"init_timeout_s": 120, "query_timeout_s": 20, "max_output_chars": 6000, **kwargs}
    return GraphRunner(str(exe.path), **limits)


def env_of(call: dict) -> dict:
    return {k.upper(): v for k, v in call["env"].items() if not k.startswith(("=", "__PYVENV"))}


class TestRunnerInvocation:
    def test_init_runs_only_the_init_command(self, fake, root):
        result = make_runner(fake).init(root)

        assert result.ok is True and result.reason is None
        [call] = fake.calls()
        assert call["argv"] == ["init", "-y", str(root)]

    def test_explore_runs_the_bounded_explore_command(self, fake, root):
        result = make_runner(fake).explore(root, "find   user  by name")

        assert result.ok is True
        assert "RESULT-TOKEN" in result.text
        [call] = fake.calls()
        assert call["argv"] == ["explore", "-p", str(root), "--max-files", "8", "--", "find user by name"]

    @pytest.mark.parametrize("query", ["", "   ", "\t\n"])
    def test_empty_query_is_rejected(self, query):
        with pytest.raises(ValueError):
            sanitize_query(query)

    @pytest.mark.parametrize("length", [299, 300])
    def test_query_up_to_300_characters_is_kept_whole(self, length):
        assert sanitize_query("a" * length) == "a" * length

    @pytest.mark.parametrize("length", [301, 1000])
    def test_longer_query_is_cut_to_exactly_300_characters(self, length):
        assert sanitize_query("a" * length) == "a" * 300

    def test_cut_query_has_no_trailing_space(self):
        cleaned = sanitize_query("word " * 100)

        assert len(cleaned) <= 300
        assert cleaned == cleaned.rstrip()
        assert cleaned.startswith("word word")

    def test_disallowed_characters_are_removed_before_spaces_are_collapsed(self):
        assert sanitize_query("foo ' bar & baz") == "foo bar baz"
        assert sanitize_query("a" * 150 + " & " + "b" * 200) == "a" * 150 + " " + "b" * 149

    def test_whitespace_runs_including_newlines_collapse_to_single_spaces(self):
        assert sanitize_query("find\n\n  user\tby   name") == "find user by name"

    def test_non_ascii_characters_are_dropped(self):
        assert sanitize_query("café user") == "caf user"

    def test_query_keeps_allowed_characters(self):
        text = "Foo_bar.baz,qux:a/b@c#d+e=f-g 1"
        assert sanitize_query(text) == text

    @pytest.mark.parametrize("hostile", ["a & b", "a | b", "a ^ b", "%PATH%", 'a "b"', "a ; b", "a `b`", "$(b)", "a > b", "a < b", "(a)", "!a!"])
    def test_query_never_carries_shell_metacharacters(self, hostile):
        cleaned = sanitize_query(f"find {hostile} user")

        assert not set(cleaned) & set('&|^%"\';`$<>()!\\*?[]{}~')
        assert cleaned.split()[0] == "find" and cleaned.split()[-1] == "user"
        assert "  " not in cleaned

    def test_metacharacters_do_not_reach_the_windows_shim_shell(self, fake, root, tmp_path):
        marker = tmp_path / "pwned.txt"
        make_runner(fake).explore(root, f"x & echo hacked > {marker}")

        assert not marker.exists()

    def test_missing_binary_reports_missing(self, tmp_path, root):
        runner = GraphRunner(
            str(tmp_path / "does-not-exist"), init_timeout_s=120, query_timeout_s=20, max_output_chars=6000
        )

        assert runner.available() is False
        result = runner.init(root)
        assert (result.ok, result.reason) == (False, "missing")

    def test_availability_check_does_not_launch_the_binary(self, fake):
        assert make_runner(fake).available() is True
        assert fake.calls() == []

    def test_nonzero_exit_reports_nonzero(self, fake, root):
        fake.configure(exit=3, stdout="partial")

        result = make_runner(fake).explore(root, "q")

        assert (result.ok, result.reason) == (False, "nonzero")


class TestRunnerClassification:
    @pytest.mark.parametrize("silent", ["", "   \n\t "])
    def test_explore_with_blank_output_is_a_successful_no_match(self, fake, root, silent):
        fake.configure(stdout=silent)

        result = make_runner(fake).explore(root, "q")

        assert (result.ok, result.reason, result.text.strip()) == (True, "no_match", "")

    def test_init_with_blank_output_is_plain_success(self, fake, root):
        fake.configure(stdout="")

        result = make_runner(fake).init(root)

        assert (result.ok, result.reason) == (True, None)

    def test_executable_that_cannot_be_launched_reports_launch_failed_and_cleans_up(
        self, tmp_path, root, monkeypatch
    ):
        scratch_parent = tmp_path / "scratch-parent"
        scratch_parent.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(scratch_parent))
        broken = tmp_path / ("broken.exe" if os.name == "nt" else "broken")
        broken.write_bytes(b"" if os.name == "nt" else b"\x00not an executable image\n")
        broken.chmod(broken.stat().st_mode | stat.S_IXUSR)
        runner = GraphRunner(str(broken), init_timeout_s=20, query_timeout_s=20, max_output_chars=6000)
        assert runner.available() is True

        result = runner.init(root)

        assert (result.ok, result.reason) == (False, "launch_failed")
        assert list(scratch_parent.iterdir()) == []

    @pytest.mark.parametrize(
        "limits",
        [
            {},
            {"init_timeout_s": 1},
            {"init_timeout_s": 1, "query_timeout_s": 1},
            {"init_timeout_s": 1, "max_output_chars": 1024},
            {"query_timeout_s": 1, "max_output_chars": 1024},
        ],
    )
    def test_timeouts_and_output_cap_must_be_given_explicitly(self, fake, limits):
        with pytest.raises(TypeError):
            GraphRunner(str(fake.path), **limits)

    def test_limits_are_keyword_only(self, fake):
        with pytest.raises(TypeError):
            GraphRunner(str(fake.path), 120, 20, 6000)


class TestRunnerEnvironment:
    def test_child_gets_allowlisted_environment_only(self, fake, root, monkeypatch):
        for key, value in {
            "GITHUB_TOKEN": "ghp_secret", "OPENAI_API_KEY": "sk-secret", "SOME_SECRET": "s",
            "OLLAMA_HOST": "http://x", "HTTPS_PROXY": "http://user:pw@proxy", "HTTP_PROXY": "http://p",
            "NODE_OPTIONS": "--require evil.js", "NODE_PATH": "/evil", "CUSTOM_VAR": "custom",
            "LC_ALL": "C", "LANG": "C",
            "HOME": "/parent/home", "USERPROFILE": "C:/parent/profile", "XDG_CONFIG_HOME": "/parent/xdg",
        }.items():
            monkeypatch.setenv(key, value)

        make_runner(fake).init(root)

        env = env_of(fake.calls()[0])
        shim_defined = {"PROMPT"} if os.name == "nt" else set()  # cmd.exe injects PROMPT into the .cmd shim's environment
        if sys.platform == "darwin":
            # /bin/sh exports PWD and SHLVL into the shim's environment, and
            # macOS injects __CF_USER_TEXT_ENCODING into every process.
            shim_defined |= {"PWD", "SHLVL", "__CF_USER_TEXT_ENCODING"}
        extra = {k for k in env if k not in ALLOWED_ENV and not k.startswith("LC_") and k not in shim_defined}
        assert extra == set()
        assert env["PATH"] == os.environ["PATH"]
        assert env["LANG"] == "C" and env.get("LC_ALL") == "C"
        for key in ("CODEGRAPH_NO_UPDATE_CHECK", "DO_NOT_TRACK", "CODEGRAPH_NO_DAEMON", "CODEGRAPH_NO_WATCH"):
            assert env[key] == "1"

    def test_every_allowlisted_variable_reaches_the_child_unchanged(self, fake, root, monkeypatch):
        expected = {}
        for key in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP", "LANG"):
            if key not in {name.upper() for name in os.environ}:
                monkeypatch.setenv(key, f"value-of-{key}")
            expected[key] = {k.upper(): v for k, v in os.environ.items()}[key]
        monkeypatch.setenv("LC_MESSAGES", "en_US.UTF-8")
        expected["LC_MESSAGES"] = "en_US.UTF-8"

        make_runner(fake).init(root)

        env = env_of(fake.calls()[0])
        assert {key: env.get(key) for key in expected} == expected
        assert env["PATH"] == os.environ["PATH"]

    def test_hostile_parent_hardening_values_are_overridden(self, fake, root, monkeypatch):
        hardening = ("CODEGRAPH_NO_UPDATE_CHECK", "DO_NOT_TRACK", "CODEGRAPH_NO_DAEMON", "CODEGRAPH_NO_WATCH")
        for key in hardening:
            monkeypatch.setenv(key, "0")

        make_runner(fake).init(root)

        env = env_of(fake.calls()[0])
        assert {key: env[key] for key in hardening} == dict.fromkeys(hardening, "1")

    def test_home_directories_are_private_and_distinct_from_the_parent(self, fake, root, monkeypatch):
        parents = {"HOME": "/parent/home", "USERPROFILE": "C:/parent/profile", "XDG_CONFIG_HOME": "/parent/xdg"}
        for key, value in parents.items():
            monkeypatch.setenv(key, value)

        make_runner(fake).init(root)

        call = fake.calls()[0]
        env = env_of(call)
        for key in PRIVATE_HOME_KEYS:
            assert env[key] != parents[key]
            assert Path(env[key]).resolve() != Path(root).resolve()
            assert not Path(env[key]).resolve().is_relative_to(Path(root).resolve())
        assert call["home_is_dir"] is True

    def test_child_runs_in_a_private_directory_with_stdin_closed(self, fake, root):
        make_runner(fake).init(root)

        call = fake.calls()[0]
        cwd = Path(call["cwd"]).resolve()
        assert cwd != Path(root).resolve()
        assert not cwd.is_relative_to(Path(root).resolve())
        assert cwd != Path.cwd().resolve()
        assert call["stdin_len"] == 0

    def test_private_directories_are_removed_after_success_and_timeout(self, fake, root):
        runner = make_runner(fake, query_timeout_s=1)
        runner.init(root)
        fake.configure(hang=60)
        runner.explore(root, "q")

        for call in fake.calls():
            env = env_of(call)
            assert not Path(env["HOME"]).exists()
            assert not Path(call["cwd"]).exists()


class TestRunnerProcessLifecycle:
    def test_timeout_reports_timeout_and_kills_the_process_tree(self, fake, root):
        fake.configure(hang=60, child=True)
        runner = make_runner(fake, query_timeout_s=1)

        started = time.monotonic()
        result = runner.explore(root, "q")
        elapsed = time.monotonic() - started

        assert (result.ok, result.reason) == (False, "timeout")
        assert elapsed < 20
        assert fake.child_pids()
        assert wait_all_dead(fake.all_pids()) == []

    def test_init_uses_the_init_timeout(self, fake, root):
        fake.configure(hang=60)
        runner = make_runner(fake, init_timeout_s=1, query_timeout_s=60)

        result = runner.init(root)

        assert (result.ok, result.reason) == (False, "timeout")

    def test_successful_command_leaves_no_descendant_running(self, fake, root):
        fake.configure(child=True, stdout="done")

        result = make_runner(fake).explore(root, "q")

        assert result.ok is True
        assert fake.child_pids()
        assert wait_all_dead(fake.child_pids()) == []

    def test_successful_command_with_a_descendant_holding_the_pipes_returns_promptly(self, fake, root):
        fake.configure(child=True, child_holds_pipes=True, stdout="done")

        started = time.monotonic()
        result = make_runner(fake).explore(root, "q")
        elapsed = time.monotonic() - started

        assert result.ok is True and "done" in result.text
        assert elapsed < 5
        assert fake.child_pids()
        assert wait_all_dead(fake.child_pids()) == []

    def test_interrupt_propagates_and_reaps_the_process_tree(self, fake, root):
        fake.configure(hang=60, child=True)
        runner = make_runner(fake, query_timeout_s=60)

        def interrupt_once_child_exists():
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and not fake.child_pids():
                time.sleep(0.05)
            _thread.interrupt_main()

        thread = threading.Thread(target=interrupt_once_child_exists, daemon=True)
        thread.start()
        started = time.monotonic()
        with pytest.raises(KeyboardInterrupt):
            runner.explore(root, "q")
        thread.join(timeout=5)

        assert time.monotonic() - started < 30
        assert wait_all_dead(fake.all_pids()) == []
        for call in fake.calls():
            assert not Path(env_of(call)["HOME"]).exists()


class TestFailedCallLeavesNoChildRunning:
    @pytest.fixture
    def fake_codegraph(self, monkeypatch):
        fake_processes = FakeCodegraph()
        monkeypatch.setattr(shutil, "which", lambda binary: binary)
        monkeypatch.setattr(runner_module, "subprocess", fake_processes.namespace)
        monkeypatch.setattr(os, "killpg", fake_processes.killpg, raising=False)
        monkeypatch.setattr(runner_module, "_assign_job", lambda pid: pid)
        monkeypatch.setattr(runner_module, "_close_handle", fake_processes.kill_tree)
        yield fake_processes
        fake_processes.kill_all()

    @pytest.mark.parametrize(
        ("command", "plan", "reason"),
        [
            ("explore", {"hangs": True}, "timeout"),
            ("explore", {"hangs": True, "descendant": True}, "timeout"),
            ("init", {"hangs": True, "descendant": True}, "timeout"),
            ("explore", {"exit_code": 3}, "nonzero"),
            ("explore", {"exit_code": 3, "descendant": True}, "nonzero"),
            ("init", {"exit_code": 1, "descendant": True}, "nonzero"),
        ],
    )
    def test_timed_out_or_failed_call_reports_the_failure_with_no_process_left(
        self, fake_codegraph, root, command, plan, reason
    ):
        fake_codegraph._plans.append(plan)
        runner = GraphRunner("codegraph", init_timeout_s=0.2, query_timeout_s=0.2, max_output_chars=6000)

        result = runner.init(root) if command == "init" else runner.explore(root, "q")

        assert (result.ok, result.reason) == (False, reason)
        assert len(fake_codegraph.processes) == 1
        assert fake_codegraph.running() == []

    def test_interrupted_call_propagates_with_no_process_left(self, fake_codegraph, root):
        fake_codegraph._plans.append({"hangs": True, "descendant": True, "interrupt": True})
        runner = GraphRunner("codegraph", init_timeout_s=60, query_timeout_s=60, max_output_chars=6000)

        with pytest.raises(KeyboardInterrupt):
            runner.explore(root, "q")

        assert len(fake_codegraph.processes) == 1
        assert fake_codegraph.running() == []

    def test_failed_call_leaves_nothing_of_an_earlier_failed_call_running_for_the_next(self, fake_codegraph, root):
        fake_codegraph._plans.extend([{"hangs": True, "descendant": True}, {"exit_code": 2, "descendant": True}, {}])
        runner = GraphRunner("codegraph", init_timeout_s=0.2, query_timeout_s=0.2, max_output_chars=6000)

        reasons = [runner.explore(root, "q").reason for _ in range(3)]

        assert reasons == ["timeout", "nonzero", "no_match"]
        assert len(fake_codegraph.processes) == 3
        assert fake_codegraph.running() == []


class TestRunnerOutputBounds:
    @pytest.mark.parametrize("limit", [1024, 6000])
    def test_stdout_flood_is_bounded_and_counted(self, fake, root, limit):
        total = 3_000_000
        fake.configure(stdout_flood=total)

        result = make_runner(fake, max_output_chars=limit).explore(root, "q")

        assert result.ok is True
        assert 0 < len(result.text) <= limit
        assert result.truncated is True
        assert result.omitted_chars >= total - limit
        assert result.text.count("[TRUNCATED]") == 1

    def test_output_of_exactly_the_limit_is_kept_whole(self, fake, root):
        fake.configure(stdout="a" * 6000)

        result = make_runner(fake).explore(root, "q")

        assert (result.text, result.truncated, result.omitted_chars) == ("a" * 6000, False, 0)

    def test_output_one_character_over_the_limit_is_truncated_with_one_marker(self, fake, root):
        fake.configure(stdout="a" * 6001)

        result = make_runner(fake).explore(root, "q")

        assert result.truncated is True
        assert len(result.text) <= 6000
        assert result.text.count("[TRUNCATED]") == 1
        assert 1 <= result.omitted_chars <= 100

    def test_limit_counts_characters_not_bytes(self, fake, root):
        fake.configure(stdout="é" * 6000)

        result = make_runner(fake).explore(root, "q")

        assert (result.text, result.truncated, result.omitted_chars) == ("é" * 6000, False, 0)

    def test_truncated_multibyte_output_is_cut_on_characters(self, fake, root):
        fake.configure(stdout="é" * 7000)

        result = make_runner(fake).explore(root, "q")

        assert result.truncated is True
        assert "�" not in result.text
        assert 5900 <= len(result.text) <= 6000
        assert result.text.count("[TRUNCATED]") == 1
        assert 1000 <= result.omitted_chars <= 1100

    def test_small_output_is_not_marked_truncated(self, fake, root):
        result = make_runner(fake).explore(root, "q")

        assert (result.truncated, result.omitted_chars) == (False, 0)

    def test_simultaneous_stream_floods_do_not_deadlock(self, fake, root):
        fake.configure(stdout_flood=4_000_000, stderr_flood=4_000_000)
        runner = make_runner(fake, query_timeout_s=60)

        started = time.monotonic()
        result = runner.explore(root, "q")

        assert result.ok is True
        assert time.monotonic() - started < 30
        assert wait_all_dead(fake.all_pids()) == []

    def test_stderr_content_never_appears_in_the_outcome(self, fake, root):
        fake.configure(stdout="fine", stderr="SECRET-FROM-STDERR " + FLOOD_TOKEN * 5000, exit=0)
        ok = make_runner(fake).explore(root, "q")
        fake.configure(stdout="fine", stderr="SECRET-FROM-STDERR " + FLOOD_TOKEN * 5000, exit=2)
        bad = make_runner(fake).explore(root, "q")

        for result in (ok, bad):
            assert "SECRET-FROM-STDERR" not in repr(result)
            assert FLOOD_TOKEN not in repr(result)

    def test_debug_logging_keeps_at_most_500_characters_of_stderr(self, fake, root, caplog):
        fake.configure(stdout="fine", stderr=FLOOD_TOKEN * 5000, exit=2)

        with caplog.at_level(logging.DEBUG):
            make_runner(fake).explore(root, "q")

        logged = "\n".join(record.getMessage() for record in caplog.records)
        assert logged.count(FLOOD_TOKEN) * len(FLOOD_TOKEN) <= 500


def graph_session(git_repo, runner, *, export=export_snapshot, **config) -> GraphSession:
    shas = resolve_refs(git_repo, "main", "pr")
    return GraphSession(git_repo, shas, LGTMConfig(**config), runner=runner, export=export)


class TestSessionLaziness:
    def test_unused_session_has_no_side_effects_and_zero_index_time(self, git_repo):
        runner = FakeRunner()
        exported = []

        def spy(*args, **kwargs):
            exported.append(args)
            return export_snapshot(*args, **kwargs)

        with graph_session(git_repo, runner, export=spy) as session:
            assert session.state == "ok"
            assert session.init_seconds == 0.0
            assert session.available is True

        assert runner.calls == [] and exported == []

    def test_missing_binary_is_unavailable_without_export_or_launch(self, git_repo, tmp_path):
        exported = []

        def spy(*args, **kwargs):
            exported.append(args)
            return export_snapshot(*args, **kwargs)

        shas = resolve_refs(git_repo, "main", "pr")
        config = LGTMConfig(graph_binary=str(tmp_path / "no-such-codegraph"))
        with GraphSession(git_repo, shas, config, export=spy) as session:
            assert session.available is False
            assert session.state == "unavailable:missing"
            result = session.explore("pr", "find user")
            assert (result.ok, result.reason) == (False, "missing")

        assert exported == []

    def test_each_snapshot_is_exported_and_initialised_once_from_its_own_commit(self, git_repo):
        runner = FakeRunner()

        with graph_session(git_repo, runner) as session:
            session.explore("base", "q1")
            session.explore("base", "q2")
            session.explore("pr", "q3")
            session.explore("pr", "q4")

        assert runner.count("init", "base") == 1 and runner.count("init", "pr") == 1
        assert runner.count("explore", "base") == 2 and runner.count("explore", "pr") == 2
        for call in runner.calls:
            assert call["root_existed"] is True
            assert ("find_user" in call["app_py"]) == (call["label"] == "pr")
        roots = {c["label"]: c["root"] for c in runner.calls}
        assert roots["base"] != roots["pr"]

    def test_initialisation_precedes_exploration_of_a_snapshot(self, git_repo):
        runner = FakeRunner()

        with graph_session(git_repo, runner) as session:
            session.explore("pr", "q")

        assert [c["kind"] for c in runner.calls] == ["init", "explore"]


class TestSessionOutcomesAndLatches:
    def test_successful_explore_returns_graph_output(self, git_repo):
        with graph_session(git_repo, FakeRunner()) as session:
            result = session.explore("pr", "find user")

        assert result.ok is True
        assert "RESULT-TOKEN" in result.text

    def test_no_match_is_success_and_does_not_latch(self, git_repo):
        runner = FakeRunner(explore={"pr": no_match()})

        with graph_session(git_repo, runner) as session:
            first = session.explore("pr", "nothing here")
            second = session.explore("pr", "still nothing")
            state = session.state

        assert (first.ok, first.reason) == (True, "no_match")
        assert second.ok is True
        assert state == "ok"
        assert runner.count("explore", "pr") == 2

    def test_init_failure_latches_its_snapshot_only_without_retry(self, git_repo):
        runner = FakeRunner(init={"pr": failure("timeout")})

        with graph_session(git_repo, runner) as session:
            first = session.explore("pr", "q1")
            second = session.explore("pr", "q2")
            other = session.explore("base", "q3")
            state = session.state

        assert first.ok is False and first.reason == "timeout"
        assert second.ok is False
        assert runner.count("init", "pr") == 1
        assert runner.count("explore", "pr") == 0
        assert other.ok is True
        assert state == "degraded:pr:timeout"

    def test_query_failure_latches_its_snapshot_only_without_retry(self, git_repo):
        runner = FakeRunner(explore={"base": failure("nonzero")})

        with graph_session(git_repo, runner) as session:
            first = session.explore("base", "q1")
            second = session.explore("base", "q2")
            other = session.explore("pr", "q3")
            state = session.state

        assert (first.ok, first.reason) == (False, "nonzero")
        assert second.ok is False
        assert runner.count("explore", "base") == 1
        assert other.ok is True
        assert state == "degraded:base:nonzero"

    def test_export_failure_latches_its_snapshot_without_init_or_retry(self, git_repo):
        attempts = []

        def failing_export(repo, sha, destination, **kwargs):
            attempts.append(sha)
            if len(attempts) == 1:
                raise ValueError("export_failed")
            return export_snapshot(repo, sha, destination, **kwargs)

        runner = FakeRunner()
        with graph_session(git_repo, runner, export=failing_export) as session:
            first = session.explore("base", "q1")
            second = session.explore("base", "q2")
            other = session.explore("pr", "q3")
            state = session.state

        assert (first.ok, first.reason) == (False, "export_failed")
        assert second.ok is False
        assert len(attempts) == 2
        assert runner.count("init", "base") == 0
        assert other.ok is True
        assert state == "degraded:base:export_failed"

    def test_launch_failure_latches_both_snapshots_keeping_earlier_reasons(self, git_repo):
        runner = FakeRunner(
            explore={"pr": failure("timeout")},
            init={"base": failure("launch_failed")},
        )

        with graph_session(git_repo, runner) as session:
            session.explore("pr", "q1")
            session.explore("base", "q2")
            entries = session.state.split(";")
            later_pr = session.explore("pr", "q3")
            later_base = session.explore("base", "q4")

        assert entries[0] == "degraded:pr:timeout"
        assert sorted(entries) == ["degraded:base:launch_failed", "degraded:pr:timeout"]
        assert later_pr.ok is False and later_base.ok is False
        assert runner.count("explore", "pr") == 1 and runner.count("explore", "base") == 0

    def test_launch_failure_on_a_fresh_session_degrades_both_snapshots(self, git_repo):
        runner = FakeRunner(init={"pr": failure("launch_failed")})

        with graph_session(git_repo, runner) as session:
            session.explore("pr", "q1")
            base = session.explore("base", "q2")
            entries = session.state.split(";")

        assert base.ok is False
        assert sorted(entries) == ["degraded:base:launch_failed", "degraded:pr:launch_failed"]
        assert runner.count("init", "base") == 0

    def test_state_lists_failures_in_first_failure_order_and_earlier_stamps_stay(self, git_repo):
        runner = FakeRunner(explore={"base": failure("timeout"), "pr": failure("nonzero")})

        with graph_session(git_repo, runner) as session:
            healthy = session.state
            session.explore("pr", "q1")
            after_pr = session.state
            session.explore("base", "q2")
            after_both = session.state

        assert healthy == "ok"
        assert after_pr == "degraded:pr:nonzero"
        assert after_both == "degraded:pr:nonzero;degraded:base:timeout"

    def test_ok_state_does_not_require_initialisation(self, git_repo):
        with graph_session(git_repo, FakeRunner()) as session:
            assert session.state == "ok"
            session.explore("pr", "q")
            assert session.state == "ok"

    def test_partial_export_stays_usable_and_exposes_its_incomplete_export(self, git_repo):
        runner = FakeRunner()

        with graph_session(git_repo, runner, graph_max_export_files=1) as session:
            result = session.explore("base", "q")
            state = session.state
            exported = session.snapshot("base")

        assert result.ok is True and "RESULT-TOKEN" in result.text
        assert "[INCOMPLETE]" not in result.text
        assert state == "ok"
        assert runner.count("explore", "base") == 1
        assert exported is not None
        assert exported.truncated or exported.incomplete
        assert exported.root == runner.calls[0]["root"]

    def test_complete_export_exposes_no_incomplete_state(self, git_repo):
        with graph_session(git_repo, FakeRunner()) as session:
            result = session.explore("base", "q")
            exported = session.snapshot("base")

        assert "[INCOMPLETE]" not in result.text
        assert exported is not None
        assert not exported.truncated and not exported.incomplete
        assert exported.skipped == ()


class TestSessionSnapshotExport:
    def test_snapshot_is_none_before_any_export(self, git_repo):
        with graph_session(git_repo, FakeRunner()) as session:
            assert session.snapshot("base") is None
            assert session.snapshot("pr") is None

    def test_snapshot_exposes_the_export_result_for_the_explored_label_only(self, git_repo):
        runner = FakeRunner()

        with graph_session(git_repo, runner) as session:
            session.explore("pr", "q")
            exported = session.snapshot("pr")
            other = session.snapshot("base")

        assert exported is not None
        assert exported.root == runner.calls[0]["root"]
        assert exported.file_count >= 1
        assert other is None

    def test_snapshot_is_none_after_export_failure(self, git_repo):
        def failing_export(*args, **kwargs):
            raise ValueError("export_failed")

        with graph_session(git_repo, FakeRunner(), export=failing_export) as session:
            session.explore("base", "q")
            assert session.snapshot("base") is None


class TestSessionTimings:
    def test_failed_initialisation_counts_as_index_time_and_excludes_explore(self, git_repo):
        runner = FakeRunner(init={"pr": failure("timeout")}, init_delay=0.2, explore_delay=0.5)

        with graph_session(git_repo, runner) as session:
            session.explore("pr", "q")
            failed_init = session.init_seconds
            session.explore("base", "q")
            both = session.init_seconds

        assert 0.15 <= failed_init < 0.45
        assert 0.35 <= both < 0.9

    def test_export_time_is_separate_from_index_time(self, git_repo):
        def slow_export(*args, **kwargs):
            time.sleep(0.4)
            return export_snapshot(*args, **kwargs)

        runner = FakeRunner(init_delay=0.1)
        with graph_session(git_repo, runner, export=slow_export) as session:
            session.explore("pr", "q")
            export_seconds, init_seconds = session.export_seconds, session.init_seconds

        assert export_seconds >= 0.35
        assert 0.08 <= init_seconds < 0.35

    def test_unused_session_reports_zero_export_time(self, git_repo):
        with graph_session(git_repo, FakeRunner()) as session:
            assert session.export_seconds == 0.0


class TestSessionCleanup:
    def test_close_removes_exported_snapshots_and_is_idempotent(self, git_repo):
        runner = FakeRunner()
        session = graph_session(git_repo, runner)
        session.explore("base", "q")
        session.explore("pr", "q")
        roots = runner.roots()
        assert roots and all(r.exists() for r in roots)

        session.close()
        session.close()

        assert not any(r.exists() for r in roots)

    def test_interrupt_during_exploration_still_removes_snapshots(self, git_repo):
        def interrupted(label, root):
            raise KeyboardInterrupt

        runner = FakeRunner(explore={"pr": interrupted})

        with pytest.raises(KeyboardInterrupt):
            with graph_session(git_repo, runner) as session:
                session.explore("pr", "q")

        assert runner.roots()
        assert not any(r.exists() for r in runner.roots())

    @pytest.mark.skipif(
        os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0), reason="needs POSIX non-root"
    )
    def test_read_only_directories_in_a_snapshot_do_not_block_cleanup(self, git_repo):
        locked = []

        def make_read_only(label, root):
            os.chmod(root / "app.py", 0o444)
            os.chmod(root, 0o555)
            locked.append(root)
            return success()

        runner = FakeRunner(init={"base": make_read_only})
        try:
            with graph_session(git_repo, runner) as session:
                session.explore("base", "q")
        finally:
            for path in locked:
                if path.exists():
                    os.chmod(path, 0o755)

        assert not any(r.exists() for r in runner.roots())

    def test_read_only_files_in_a_snapshot_do_not_block_cleanup(self, git_repo):
        def make_read_only(label, root):
            target = root / "app.py"
            os.chmod(target, 0o444)
            return success()

        runner = FakeRunner(init={"base": make_read_only})
        with graph_session(git_repo, runner) as session:
            session.explore("base", "q")

        assert not any(r.exists() for r in runner.roots())


class TestSessionWithRealRunnerAndFakeExecutable:
    def test_end_to_end_with_real_export_and_process_runner(self, git_repo, tmp_path):
        exe = make_fake_executable(tmp_path / "bin", stdout="RESULT-TOKEN")
        try:
            shas = resolve_refs(git_repo, "main", "pr")
            config = LGTMConfig(graph_binary=str(exe.path), graph_query_timeout_s=20)
            with GraphSession(git_repo, shas, config) as session:
                assert session.available is True
                result = session.explore("pr", "find user")
                state = session.state

            assert result.ok is True and "RESULT-TOKEN" in result.text
            assert state == "ok"
            kinds = [c["argv"][0] for c in exe.calls()]
            assert kinds == ["init", "explore"]
            root = Path(exe.calls()[0]["argv"][2])
            assert not root.exists()
        finally:
            kill_pids(exe.all_pids())

    def test_default_runner_takes_its_output_cap_from_the_config(self, git_repo, tmp_path):
        exe = make_fake_executable(tmp_path / "bin", stdout="y" * 3000)
        try:
            shas = resolve_refs(git_repo, "main", "pr")
            config = LGTMConfig(graph_binary=str(exe.path), graph_max_output_chars=1024)
            with GraphSession(git_repo, shas, config) as session:
                result = session.explore("pr", "find user")

            assert result.ok is True and result.truncated is True
            assert 0 < len(result.text) <= 1024
        finally:
            kill_pids(exe.all_pids())

    @pytest.mark.parametrize("slow", ["init", "explore"])
    def test_default_runner_uses_the_configured_timeout_for_each_command(self, git_repo, tmp_path, slow):
        exe = make_fake_executable(tmp_path / "bin", hang=60, hang_only=slow)
        init_limit, query_limit = (1, 60) if slow == "init" else (60, 1)
        try:
            shas = resolve_refs(git_repo, "main", "pr")
            config = LGTMConfig(
                graph_binary=str(exe.path), graph_init_timeout_s=init_limit, graph_query_timeout_s=query_limit
            )
            started = time.monotonic()
            with GraphSession(git_repo, shas, config) as session:
                result = session.explore("pr", "find user")
                state = session.state

            assert (result.ok, result.reason) == (False, "timeout")
            assert state == "degraded:pr:timeout"
            assert time.monotonic() - started < 20
        finally:
            kill_pids(exe.all_pids())

    def test_timeout_in_real_runner_degrades_only_that_snapshot(self, git_repo, tmp_path):
        exe = make_fake_executable(tmp_path / "bin", hang=60, child=True)
        try:
            shas = resolve_refs(git_repo, "main", "pr")
            config = LGTMConfig(graph_binary=str(exe.path), graph_init_timeout_s=1, graph_query_timeout_s=1)
            with GraphSession(git_repo, shas, config) as session:
                result = session.explore("pr", "find user")
                state = session.state

            assert (result.ok, result.reason) == (False, "timeout")
            assert state == "degraded:pr:timeout"
            assert wait_all_dead(exe.all_pids()) == []
        finally:
            kill_pids(exe.all_pids())


@pytest.mark.requires_codegraph
@pytest.mark.skipif(shutil.which("codegraph") is None, reason="codegraph binary not installed")
def test_real_codegraph_indexes_and_explores_a_snapshot(git_repo):
    shas = resolve_refs(git_repo, "main", "pr")
    with GraphSession(git_repo, shas, LGTMConfig()) as session:
        result = session.explore("pr", "find_user")
        assert isinstance(result, GraphOutcome)
        assert result.ok is True


class TestScratchRemoval:
    def test_removal_is_retried_until_it_succeeds(self, tmp_path, monkeypatch):
        target = tmp_path / "scratch"
        target.mkdir()
        real_rmtree = shutil.rmtree
        attempts = []

        def flaky(path, *args, **kwargs):
            attempts.append(path)
            if len(attempts) < 3:
                raise PermissionError("busy")
            return real_rmtree(path, *args, **kwargs)

        monkeypatch.setattr(shutil, "rmtree", flaky)

        remove_tree(target)

        assert len(attempts) == 3
        assert not target.exists()

    def test_persistent_removal_failure_is_logged_after_three_attempts_without_raising(
        self, tmp_path, monkeypatch, caplog
    ):
        target = tmp_path / "scratch"
        target.mkdir()
        attempts = []

        def always_fails(path, *args, **kwargs):
            attempts.append(path)
            raise PermissionError("busy")

        monkeypatch.setattr(shutil, "rmtree", always_fails)

        with caplog.at_level(logging.WARNING):
            remove_tree(target)

        assert len(attempts) == 3
        assert any(record.levelno >= logging.WARNING for record in caplog.records)

    def test_removal_does_not_follow_a_link_to_a_directory_outside_the_tree(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        keep = outside / "keep.txt"
        keep.write_text("precious", encoding="utf-8")
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "file.txt").write_text("x", encoding="utf-8")
        try:
            os.symlink(outside, tree / "link", target_is_directory=True)
        except (OSError, NotImplementedError):
            pytest.skip("host denies symlink creation")

        remove_tree(tree)

        assert not tree.exists()
        assert keep.read_text(encoding="utf-8") == "precious"

    @pytest.mark.skipif(os.name != "nt", reason="directory junctions are Windows-only")
    def test_removal_does_not_follow_a_junction_to_a_directory_outside_the_tree(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        keep = outside / "keep.txt"
        keep.write_text("precious", encoding="utf-8")
        keep.chmod(stat.S_IREAD)
        tree = tmp_path / "tree"
        tree.mkdir()
        (tree / "file.txt").write_text("x", encoding="utf-8")
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(tree / "junction"), str(outside)],
            capture_output=True,
            check=False,
        )
        if made.returncode != 0 or not (tree / "junction").exists():
            pytest.skip("junction creation failed")
        try:
            remove_tree(tree)

            assert not tree.exists()
            assert outside.is_dir()
            assert keep.read_text(encoding="utf-8") == "precious"
            assert not os.access(keep, os.W_OK)
        finally:
            keep.chmod(stat.S_IWRITE)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX directory permission bits")
    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores permission bits")
    def test_read_only_directory_containing_files_is_removed(self, tmp_path):
        tree = tmp_path / "tree"
        locked = tree / "locked"
        (locked / "nested").mkdir(parents=True)
        (locked / "a.txt").write_text("a", encoding="utf-8")
        (locked / "nested" / "b.txt").write_text("b", encoding="utf-8")
        (locked / "nested").chmod(0o555)
        locked.chmod(0o555)
        try:
            remove_tree(tree)

            assert not tree.exists()
        finally:
            for path in (locked / "nested", locked):
                if path.exists():
                    path.chmod(0o755)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX symlink and permission semantics")
    @pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="root ignores permission bits")
    def test_removal_error_handling_leaves_outside_directories_untouched(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        keep = outside / "keep.txt"
        keep.write_text("precious", encoding="utf-8")
        outside.chmod(0o555)
        tree = tmp_path / "tree"
        locked = tree / "locked"
        locked.mkdir(parents=True)
        os.symlink(outside, locked / "link", target_is_directory=True)
        locked.chmod(0o555)
        try:
            remove_tree(tree)

            assert stat.S_IMODE(outside.stat().st_mode) == 0o555
            assert keep.read_text(encoding="utf-8") == "precious"
        finally:
            if locked.exists():  # remove_tree may have removed it (it should)
                locked.chmod(0o755)
            outside.chmod(0o755)


@pytest.mark.skipif(os.name != "nt", reason="taskkill is the Windows termination path")
class TestTerminationWhenTaskkillIsUnavailable:
    def test_timeout_still_reaps_the_child_tree_and_returns(self, fake, root, monkeypatch):
        fake.configure(hang=60, child=True)
        real_run = subprocess.run

        def run_without_taskkill(argv, *args, **kwargs):
            if "taskkill" in os.path.basename(str(argv[0])).lower():
                raise FileNotFoundError("taskkill.exe unavailable")
            return real_run(argv, *args, **kwargs)

        runner = make_runner(fake, query_timeout_s=1)

        started = time.monotonic()
        with monkeypatch.context() as patched:
            patched.setattr(subprocess, "run", run_without_taskkill)
            result = runner.explore(root, "q")
        elapsed = time.monotonic() - started

        assert (result.ok, result.reason) == (False, "timeout")
        assert elapsed < 20
        assert fake.child_pids()
        assert wait_all_dead(fake.all_pids()) == []
