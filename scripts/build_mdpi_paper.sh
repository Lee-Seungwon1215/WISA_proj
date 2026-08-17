#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
paper_dir="$repo_root/paper/mdpi_working"
python_bin="$repo_root/.venv/bin/python"
analysis_path=""
refresh_outputs=0

usage() {
  echo "usage: bash scripts/build_mdpi_paper.sh [--refresh] [--analysis PATH]" >&2
  echo "  no --analysis: build the explicit pre-result draft" >&2
  echo "  --analysis:     require a complete validated 28-axis named analysis" >&2
}

while (($#)); do
  case "$1" in
    --analysis)
      if (($# < 2)); then
        usage
        exit 2
      fi
      analysis_path=$2
      shift 2
      ;;
    --refresh)
      refresh_outputs=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ ! -x "$python_bin" ]]; then
  python_bin=python3
fi

render_args=("$python_bin" "$repo_root/scripts/render_mdpi_results.py")
check_args=("$python_bin" "$repo_root/scripts/check_mdpi_paper.py")
if [[ -n "$analysis_path" ]]; then
  if [[ ! -f "$analysis_path" ]]; then
    echo "analysis file does not exist: $analysis_path" >&2
    exit 2
  fi
  render_args+=(--analysis "$analysis_path")
  check_args+=(--analysis "$analysis_path")
else
  check_args+=(--allow-pending)
fi

if ((refresh_outputs)); then
  "${render_args[@]}" --write
else
  "${render_args[@]}" --check
fi

"${check_args[@]}"
mkdir -p "$paper_dir/build"
(
  cd "$paper_dir"
  latexmk \
    -pdf \
    -interaction=nonstopmode \
    -halt-on-error \
    -file-line-error \
    -outdir=build \
    -jobname=CT-KAT_MDPI_draft \
    main.tex
)
"${check_args[@]}" --log "$paper_dir/build/CT-KAT_MDPI_draft.log"

echo "MDPI draft: $paper_dir/build/CT-KAT_MDPI_draft.pdf"
