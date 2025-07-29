#!/bin/bash

set -e

IMAGE_NAME=$1
TAG=$2
REGISTRY_DIR=$3
REGISTRY_URL="registry.k8s.io"
IMAGE_DIR="$REGISTRY_DIR/$IMAGE_NAME"

if [ -z "$IMAGE_NAME" ] || [ -z "$TAG" ] || [ -z "$REGISTRY_DIR" ]; then
  echo "Usage: $0 <image_name> <tag> <output_directory>"
  exit 1
fi

mkdir -p "$IMAGE_DIR/manifests"
mkdir -p "$IMAGE_DIR/blobs"

echo "Downloading manifest list for $IMAGE_NAME:$TAG..."
MANIFEST_LIST_PATH="$IMAGE_DIR/manifests/${TAG}_index"
crane manifest "$REGISTRY_URL/$IMAGE_NAME:$TAG" > "$MANIFEST_LIST_PATH"
echo "Saved manifest list to $MANIFEST_LIST_PATH"

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

echo "Image preparation complete for $IMAGE_NAME:$TAG."
