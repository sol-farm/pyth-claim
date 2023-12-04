#! /bin/bash

# enforces the linting process to apply, and fix **all** lints even if it breaks software
# note the software breakage would simply be compilation failures


__CARGO_FIX_YOLO=1
export __CARGO_FIX_YOLO=1
make -e do-lint
