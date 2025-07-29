#!/bin/bash

# Copyright 2025 The Kubernetes Authors.
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

IMAGE_NAME=$1
TAG=$2
INTERNAL_TAG=$3
REGISTRY_DIR=$4
REGISTRY_URL="registry.k8s.io"
IMAGE_DIR="$REGISTRY_DIR/$IMAGE_NAME"

if [ -z "$IMAGE_NAME" ] || [ -z "$TAG" ] || [ -z "$REGISTRY_DIR" ]; then
  echo "Usage: $0 <image_name> <tag> <output_directory>"
  exit 1
fi

mkdir -p "$IMAGE_DIR/manifests"
mkdir -p "$IMAGE_DIR/blobs"

echo "Downloading manifest list for $IMAGE_NAME:$TAG..."
MANIFEST_LIST_PATH="$IMAGE_DIR/manifests/${INTERNAL_TAG}_index"
crane manifest "$REGISTRY_URL/$IMAGE_NAME:$TAG" > "$MANIFEST_LIST_PATH"
echo "Saved manifest list to $MANIFEST_LIST_PATH"

# Calculate the digest of the manifest list and create a copy named after the digest.
# The container runtime makes second request by the digest name to the list, even if
# it's already fetched by tag name
MANIFEST_DIGEST="sha256:$(sha256sum < "$MANIFEST_LIST_PATH" | awk '{print $1}')"
cp "$MANIFEST_LIST_PATH" "$IMAGE_DIR/manifests/$MANIFEST_DIGEST"
echo "Created digest-named copy of manifest list: $MANIFEST_DIGEST"

echo "Parsing manifest list and downloading individual manifests and blobs..."
jq -r '.manifests[].digest' < "$MANIFEST_LIST_PATH" | while read -r manifest_digest; do
  # manifests
  echo "  Downloading manifest $manifest_digest..."
  INDIVIDUAL_MANIFEST_PATH="$IMAGE_DIR/manifests/$manifest_digest"
  crane manifest "$REGISTRY_URL/$IMAGE_NAME@$manifest_digest" > "$INDIVIDUAL_MANIFEST_PATH"
  echo "  Saved manifest to $INDIVIDUAL_MANIFEST_PATH"

  # configs
  CONFIG_DIGEST=$(jq -r '.config.digest' < "$INDIVIDUAL_MANIFEST_PATH")
  echo "    Downloading config blob $CONFIG_DIGEST..."
  crane blob "$REGISTRY_URL/$IMAGE_NAME@$CONFIG_DIGEST" > "$IMAGE_DIR/blobs/$CONFIG_DIGEST"
  echo "    Saved config blob to $IMAGE_DIR/blobs/$CONFIG_DIGEST"

  # blobs
  jq -r '.layers[].digest' < "$INDIVIDUAL_MANIFEST_PATH" | while read -r layer_digest; do
    echo "    Downloading layer blob $layer_digest..."
    crane blob "$REGISTRY_URL/$IMAGE_NAME@$layer_digest" > "$IMAGE_DIR/blobs/$layer_digest"
    echo "    Saved layer blob to $IMAGE_DIR/blobs/$layer_digest"
  done
done

echo "Image preparation complete for $IMAGE_NAME:$TAG with internal tag $INTERNAL_TAG."
