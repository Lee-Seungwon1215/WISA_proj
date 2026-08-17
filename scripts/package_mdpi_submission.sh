#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd)
paper_dir="$repo_root/paper/mdpi_working"
analysis_path=""
output_path="$paper_dir/build/CT-KAT_MDPI_submission_source_draft.zip"
allow_draft=0

usage() {
  echo "usage: bash scripts/package_mdpi_submission.sh --analysis PATH [--output ZIP] [--draft]" >&2
  echo "  --draft permits anonymized author/funding/DOI placeholders" >&2
}

while (($#)); do
  case "$1" in
    --analysis)
      analysis_path=${2:-}
      shift 2
      ;;
    --output)
      output_path=${2:-}
      shift 2
      ;;
    --draft)
      allow_draft=1
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

if [[ -z "$analysis_path" || ! -f "$analysis_path" ]]; then
  echo "a complete named analysis is required: $analysis_path" >&2
  exit 2
fi
if [[ -e "$output_path" ]]; then
  echo "refusing to overwrite existing package: $output_path" >&2
  exit 2
fi

bash "$repo_root/scripts/build_mdpi_paper.sh" --analysis "$analysis_path"

if (( ! allow_draft )); then
  placeholder_pattern='Anonymous Authors|withheld|must be confirmed|must be restored|stable identifier|planned supplementary'
  if grep -Eiq "$placeholder_pattern" "$paper_dir/main.tex"; then
    echo "final package blocked by unresolved human metadata or archive placeholders" >&2
    echo "use --draft only for an explicitly non-submittable review package" >&2
    exit 1
  fi
fi

stage_root=$(mktemp -d "${TMPDIR:-/tmp}/ctkat-mdpi-package.XXXXXX")
trap 'rm -rf "$stage_root"' EXIT
stage="$stage_root/CT-KAT_MDPI"
mkdir -p "$stage/generated"
cp -p "$paper_dir/main.tex" "$paper_dir/references.bib" "$paper_dir/README.md" "$paper_dir/UPSTREAM.md" "$stage/"
cp -p "$paper_dir"/generated/*.tex "$paper_dir"/generated/*.json "$stage/generated/"
cp -Rp "$paper_dir/Definitions" "$stage/Definitions"

(
  cd "$stage"
  latexmk \
    -pdf \
    -interaction=nonstopmode \
    -halt-on-error \
    -file-line-error \
    -outdir=build \
    -jobname=CT-KAT_MDPI_draft \
    main.tex
)

python_bin="$repo_root/.venv/bin/python"
if [[ ! -x "$python_bin" ]]; then
  python_bin=python3
fi
"$python_bin" "$repo_root/scripts/check_mdpi_paper.py" \
  --analysis "$analysis_path" \
  --log "$stage/build/CT-KAT_MDPI_draft.log"

mkdir -p "$(dirname "$output_path")"
output_dir=$(cd "$(dirname "$output_path")" && pwd)
output_abs="$output_dir/$(basename "$output_path")"
(
  cd "$stage"
  zip -X -q -r "$output_abs" main.tex references.bib README.md UPSTREAM.md generated Definitions
)

echo "MDPI source package: $output_abs"
shasum -a 256 "$output_abs"
