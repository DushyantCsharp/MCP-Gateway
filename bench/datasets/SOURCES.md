# Dataset sources

Third-party data used by the detection benchmark. The raw files are not
committed: they live under `bench/datasets/external/` (git-ignored) and are
fetched at the pinned versions below, so every run uses identical inputs.
The datasets built from them record these pins, and a hash of each file, in
`bench/datasets/build/manifest.json`.

| Source | Where | Pinned at | Licence | Fetched | Used for |
| --- | --- | --- | --- | --- | --- |
| InjecAgent (Zhan et al., 2024) | https://github.com/uiuc-kang-lab/InjecAgent | commit `f19c9f2c79a41046eb13c03c51a24c567a8ffa07` (2024-07-02) | MIT (`LICENCE` in the repo) | 2026-10-02 | Attack samples: indirect injections in tool responses, in two categories (direct harm, data stealing), base and enhanced variants |
| AgentDojo (Debenedetti et al., 2024) | https://github.com/ethz-spylab/agentdojo | release `v0.1.35`, installed as the `agentdojo` package (`uv sync --group bench`) | MIT (`LICENSE` in the repo) | 2026-10-02 | Not yet used. Planned for the end-to-end agent evaluation and for retrieved-document injections |

## Fetching

```bash
mkdir -p bench/datasets/external
git clone https://github.com/uiuc-kang-lab/InjecAgent.git bench/datasets/external/InjecAgent
git -C bench/datasets/external/InjecAgent checkout f19c9f2c79a41046eb13c03c51a24c567a8ffa07
uv sync --group bench    # installs agentdojo==0.1.35
```

## Licence notices

Both sources are MIT-licensed. Any redistribution of their data, including
derived datasets, must keep their copyright and permission notices. Results
that use them cite them:

- Qiusi Zhan, Zhixiang Liang, Zifan Ying, Daniel Kang. *InjecAgent:
  Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language
  Model Agents.* Findings of ACL 2024.
- Edoardo Debenedetti, Jie Zhang, Mislav Balunović, Luca Beurer-Kellner, Marc
  Fischer, Florian Tramèr. *AgentDojo: A Dynamic Environment to Evaluate
  Prompt Injection Attacks and Defenses for LLM Agents.* NeurIPS 2024
  Datasets and Benchmarks.
