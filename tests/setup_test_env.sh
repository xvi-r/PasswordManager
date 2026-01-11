#!/bin/bash

export JWT_SECRET="supersecretjwtkey"
export REFRESH_TOKEN_SECRET="supersecretrefreshkey"


pytest "$@"
