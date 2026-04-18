# StaticLab MVP Scaffold

StaticLab application with practical Phase 1 and Phase 2 support:
- upload a PE/APK sample
- save it safely
- create a SQLite job record
- compute SHA-256
- detect the real artifact type
- run Phase 1 trust analysis (hash lookup and PE signature verification)
- optionally early-exit on trusted known-good hashes
- run common analysis (YARA) when trust analysis does not early-exit
- run PE/APK structural analyzers
- write a normalized JSON report

## Expected runtime layout

This scaffold assumes the environment created by `install_staticlab.sh`:

- `/opt/staticlab/app`
- `/opt/staticlab/data/uploads`
- `/opt/staticlab/data/reports`
- `/opt/staticlab/rules`
- `/opt/staticlab/venv`

## Run

```bash
source /opt/staticlab/activate.sh
cd /opt/staticlab/app
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## First endpoints

- `GET /` upload page
- `POST /upload` create job + start background analysis
- `GET /jobs/{job_id}` HTML job view or `?format=json`
- `GET /report/{job_id}` normalized JSON report

## Notes

- AI summarization is intentionally not in this first milestone.
- The YARA loader prefers a compiled bundle if it exists, but can fall back to `.yar/.yara` files.
- The APK branch starts with metadata/permissions and keeps JADX optional.
- The PE branch is resilient if `diec`, `floss`, or `capa` are missing or fail.


## Phase 1 notes

- Hash lookup is provider-based and defaults to CIRCL Hashlookup.
- PE signature verification uses `osslsigncode` when available.
- Only known-good hash matches may early-exit analysis in this build.
- Valid signatures reduce suspicion but do not skip deeper analysis.
