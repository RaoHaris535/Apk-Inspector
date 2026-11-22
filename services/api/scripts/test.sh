#!/bin/sh
set -eu

coverage erase
coverage run -m pytest
coverage report
