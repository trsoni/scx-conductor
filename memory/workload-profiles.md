# Workload profiles: model, priors, tuning log

## Model
Classes (per tgid): `NORMAL=0, FG=1, MEDIA=2, BG=3`. Per class the BPF template takes:
`slice_ns` (time slice), `credit_ns` (max sleeper credit = wake-up boost), `charge_pct` (vtime charged per ns run; lower
= more share), `perf` (cpuperf hint 1..1024, 0 = untouched). Platform state applies `perf_cap` and `slice_scale`.

## Priors (UNTUNED - source of truth is `profiles/profiles.json`)
| workload | idea |
|---|---|
| ui | FG short slice, big sleeper credit, moderate perf |
| browser | like ui, slightly longer FG slice |
| gaming | FG shortest slice, charge 60 %, perf 1024; BG charged 180 % |
| video | steady MEDIA, lower perf (decode is periodic), BG long slices |
| camera | MEDIA shortest slice (1.5 ms) and largest credit; BG heavily deprioritised |
| graphics | FG/MEDIA balanced, perf high |
| agentic | throughput-leaning: long NORMAL slice, high perf, little demotion |
| batch | long slices, no demotion, perf max |

## Tuning log (add one row per measurement; nothing measured yet)
| date | hardware | kernel | commit | workload | metric | stock | conductor | verdict |
|---|---|---|---|---|---|---|---|---|
| - | - | - | - | - | - | - | - | none yet |

Metrics to use: frame-time p50/p99/p99.9 (games), input latency (UI), dropped frames (video/camera), tool-call tail
latency (agentic), package energy (RAPL / gauge / rails).
