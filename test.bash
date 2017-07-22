#!/bin/bash

set -e -u -o pipefail

self="$(realpath "${BASH_SOURCE[-1]}")"

self_dir="${self%/*}"
name="dockinout"

cmd=(
    #docker run --rm -i --log-driver none testcmd-image /usr/lib/openssh/sftp-server
    #"$self_dir/$name" sudo docker run --rm --network none --log-driver=none
    #    --tmpfs /tmp:rw,exec,nosuid,nodev,size=65536k
    #    -v "@@:/tmp/$name.socket" -v "$self_dir/$name:/tmp/$name:ro"
    #    ubuntu "/tmp/$name" -c "/tmp/$name.socket"
    #    bash -c 'echo 123; read -r test; echo "test=$test"'
    "/tmp/$name/$name" docker run --rm --network none --log-driver=none
        --tmpfs /tmp:rw,exec,nosuid,nodev,size=65536k
        -v "@@:/tmp/$name.socket" -v "/tmp/$name/$name:/tmp/$name:ro"
        testcmd-image "/tmp/$name" -c "/tmp/$name.socket"
        /usr/lib/openssh/sftp-server
)

rsync -rtE -e 'ssh -p 2222' "$self_dir/" "core@127.0.0.1:/tmp/$name"

exec ssh -p 2222 -T core@127.0.0.1 "${cmd[@]}"
