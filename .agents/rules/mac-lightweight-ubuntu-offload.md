---
trigger: always_on
description: Keep the Mac workspace lightweight by offloading builds, tests, and Docker verification to the Ubuntu remote server.
---

# Mac Lightweight Workspace & Ubuntu Offload Rule

1. **Keep the Mac workspace lightweight (~4 MB):**
   - Never leave heavy build artifacts (`core/target`, `tests/rust/target`, `gui/target`, `tests/js/node_modules`, `tests/__pycache__`) on the Mac.
   - If you must build or install packages locally on the Mac, clean them up before finishing (`rm -rf core/target tests/rust/target gui/target tests/js/node_modules tests/__pycache__`).
2. **Offload builds, tests, and Docker verification to Ubuntu (`ssh ubuntu`):**
   - Edit source files on the Mac, then sync:
     `rsync -az --exclude target --exclude node_modules --exclude __pycache__ core tests tools gui README.md local-cloud-emulator-plan.md AGENTS.md CONTRIBUTING.md SKILL.md Dockerfile ubuntu:~/work/projects/rocalcloud/`
   - Run full build & verification on Ubuntu (respecting `nice -n 10`, `-j 8`, RAM 8 GiB, no leftover Docker containers):
     `ssh ubuntu 'bash ~/work/projects/rocalcloud/tools/ubuntu_verify.sh'`
   - If `core/Cargo.lock` changes on Ubuntu, copy it back to the Mac (`scp ubuntu:~/work/projects/rocalcloud/core/Cargo.lock core/Cargo.lock`) and commit it.
