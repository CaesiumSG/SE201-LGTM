"""LGTM command-line interface.

Usage:
    lgtm index  --repo <path>
    lgtm review --repo <path> --base <branch> --pr <branch> \
                [--model <ollama_model>] [--gpu-model qwen3.8-27b] [--output <dir>]
                [--mode lgtm|sast-only|llm-only|lgtm-no-sast]
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click

from lgtm import __version__
from lgtm.config import GPU_MODELS, LGTMConfig, apply_gpu_model, setup_logging

logger = logging.getLogger(__name__)


@click.group()
@click.version_option(__version__, prog_name="lgtm")
def main() -> None:
    """LGTM — Context-Aware PR Security Agent."""


def _load_config(config_file: str | None, **overrides) -> LGTMConfig:
    config = LGTMConfig.from_file(config_file) if config_file else LGTMConfig()
    for key, value in overrides.items():
        if value is not None:
            setattr(config, key, value)
    return config


@main.command()
@click.option("--repo", required=True, type=click.Path(exists=True, file_okay=False), help="Path to the repository to index.")
@click.option("--config-file", type=click.Path(exists=True, dir_okay=False), default=None, help="Optional JSON config file.")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
def index(repo: str, config_file: str | None, verbose: bool) -> None:
    """Index project documentation into ChromaDB for policy retrieval."""
    setup_logging(verbose)
    from lgtm.rag.indexer import index_repo_docs

    config = _load_config(config_file)
    count = index_repo_docs(repo, config)
    click.echo(f"Indexed {count} documentation chunks from {repo}")


@main.command()
@click.option("--repo", required=True, type=click.Path(exists=True, file_okay=False), help="Path to the repository under review.")
@click.option("--base", required=True, help="Base branch (trusted).")
@click.option("--pr", required=True, help="PR branch (untrusted changes).")
@click.option("--model", default=None, help="Ollama model name (default: qwen3.8:27b).")
@click.option("--ollama-url", default=None, help="Ollama base URL.")
@click.option("--gpu-cluster", is_flag=True, help="Use the existing GPU cluster tunnel at http://127.0.0.1:11435 with qwen3.8:27b. Does not start the server or tunnel.")
@click.option("--gpu-model", type=click.Choice(sorted(GPU_MODELS)), default=None, help="Use the GPU cluster tunnel at http://127.0.0.1:11435 with a registered model (thinking off). Cannot be combined with --gpu-cluster or --model; --ollama-url overrides the URL.")
@click.option("--output", "output_dir", default=None, type=click.Path(file_okay=False), help="Output directory (default: lgtm-output).")
@click.option("--mode", type=click.Choice(["lgtm", "sast-only", "llm-only", "lgtm-no-sast"]), default="lgtm", show_default=True, help="Pipeline mode (for benchmarking baselines).")
@click.option("--semgrep-config", default=None, help="Semgrep config ('auto' or rules path).")
@click.option("--config-file", type=click.Path(exists=True, dir_okay=False), default=None, help="Optional JSON config file.")
@click.option("--strip-comments", is_flag=True, help="Mitigation: strip comments and docstrings from PR code in prompts.")
@click.option("--detect-prompt-injection", is_flag=True, help="Mitigation: detect reviewer-directed instructions in diff.")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
def review(
    repo: str,
    base: str,
    pr: str,
    model: str | None,
    ollama_url: str | None,
    gpu_cluster: bool,
    gpu_model: str | None,
    output_dir: str | None,
    mode: str,
    semgrep_config: str | None,
    config_file: str | None,
    strip_comments: bool,
    detect_prompt_injection: bool,
    verbose: bool,
) -> None:
    """Run the full security review pipeline on a PR."""
    setup_logging(verbose)
    if gpu_model and (gpu_cluster or model):
        raise click.UsageError("--gpu-model cannot be combined with --gpu-cluster or --model.")
    from lgtm.pipeline import ReviewPipeline

    if gpu_cluster:
        model = model or "qwen3.8:27b"
        ollama_url = ollama_url or "http://127.0.0.1:11435"
    config = _load_config(
        config_file,
        ollama_model=model,
        ollama_base_url=ollama_url,
        semgrep_config=semgrep_config,
    )
    if gpu_model:
        apply_gpu_model(config, gpu_model, base_url=ollama_url)
    config.mode = mode
    if strip_comments:
        config.strip_comments = True
    if detect_prompt_injection:
        config.detect_prompt_injection = True
    out = Path(output_dir or config.output_dir)

    try:
        pipeline = ReviewPipeline(repo, config)
        result = pipeline.run(base, pr, out)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        logger.error("Review failed: %s", exc, exc_info=verbose)
        click.echo(f"ERROR: {exc}", err=True)
        sys.exit(2)

    vulnerable = sum(1 for f in result.findings if f.verdict == "vulnerable")
    possible = sum(1 for f in result.findings if f.verdict == "possible")
    click.echo("")
    click.echo(f"Review complete in {result.meta.duration_seconds:.1f}s")
    click.echo(
        f"  Findings: {len(result.findings)} "
        f"(vulnerable: {vulnerable}, possible: {possible})"
    )
    if result.json_path:
        click.echo(f"  JSON report:     {result.json_path}")
        click.echo(f"  Markdown report: {result.md_path}")
    # Exit code 1 signals confirmed findings (useful in CI)
    sys.exit(1 if vulnerable else 0)


if __name__ == "__main__":
    main()
