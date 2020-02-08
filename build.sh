#!/bin/bash

# Copyright 2017 CoreOS
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e
set -o pipefail

# Generate the aci image
if [[ -z "$GOPATH" ]]
then
    echo Please set you GOPATH correctly
    exit 1
fi

execs="enter run stop udhcpc_script.sh launcher.sh mount_disk.sh"
netplugins="main/ptp main/bridge main/macvlan main/ipvlan ipam/host-local meta/flannel meta/tuning"

# Clean the repo, but save the vendor area
if [ "x${1:-}" != "x" ] && [ "clean" == "$1" ]; then
    echo "cleaning project"
    rm -rf kernel/out
    rm -rf kernel/build
    rm -rf target
    rm -f stage1-xen.aci
    rm -f aci/actool

    exit 0
fi

# Support cross-compiling via ARCH variable
if [[ -z "$ARCH" ]]
then
    ARCH=`uname -m`
fi
if [[ $ARCH = "x86_64" ]]
then
    ARCH="x86"
elif [[ $ARCH = "aarch64" ]]
then
    ARCH="arm64"
elif [[ $ARCH = "arm*" ]]
then
    ARCH="arm"
else
    echo Architecture not supported
    exit 1
fi
export ARCH

# Build up the target directory and the rootfs
if [ ! -d target ]; then
    mkdir -p target/rootfs
    mkdir -p target/rootfs/opt/stage2
    mkdir -p target/rootfs/rkt/status
    cd target/rootfs && ln -s flavor xen && cd ../..
fi

for i in $execs; do
    cp files/$i target/rootfs
done

# Build the kernel and initrd
#kernel/make-kernel
#cp kernel/out/kernel target/rootfs
kernel/make-initrd
cp kernel/out/initrd target/rootfs

cp aci/aci-manifest.in target/manifest

if [ -f stage1-xen.aci ]; then
    rm stage1-xen.aci
fi

# Build init
cd init
rm -rf vendor
[ -f go.mod ] && go mod vendor || glide install -v
go build -o ../target/rootfs/init init.go

# Network plugins
mkdir -p ../target/rootfs/usr/lib/rkt/plugins/net
for i in $netplugins
do
    go build github.com/containernetworking/cni/plugins/$i
    mv `echo $i | cut -d / -f 2` ../target/rootfs/usr/lib/rkt/plugins/net
done
cd ..

# Default network configs
mkdir -p target/rootfs/etc/rkt/net.d
cp net.d/* target/rootfs/etc/rkt/net.d

# Create flavor and systemd-version
cd target/rootfs
rm -f xen
ln -s xen flavor || true
echo 1 > systemd-version
cd ../..

# Build actool
#go get github.com/appc/spec/actool
#go build -o ./aci/actool github.com/appc/spec/actool

#./aci/actool build target stage1-xen.aci
