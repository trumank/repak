#!/bin/bash

set -a
. config.sh
set +a

unreal-version-for() {
  case "$1" in
    5)
      echo -n "$UNREAL_4_20"
      ;;
    7)
      echo -n "$UNREAL_4_21"
      ;;
    8a)
      echo -n "$UNREAL_4_22"
      ;;
    8b)
      echo -n "$UNREAL_4_23"
      ;;
    9)
      echo -n "$UNREAL_4_25"
      ;;
    11)
      echo -n "$UNREAL_4_27"
      ;;
  esac
}

generate() {
  rm -r packs && mkdir packs
  _version=(5 7 8a 8b 9 11)
  _compress=("" "-compress")
  _encrypt=("" "-encrypt")
  _encryptindex=("" "-encryptindex")
  echo "\"$(realpath "pack/*")\" \"../mount/point/\"" > input.txt
  for version in "${_version[@]}"; do
    for compress in "${_compress[@]}"; do
      for encrypt in "${_encrypt[@]}"; do
        for encryptindex in "${_encryptindex[@]}"; do
          name="$version$compress$encrypt$encryptindex"
          "$(unreal-version-for "$version")" "$(realpath "packs/pack_v${name//-/_}.pak")" -Create="$(realpath input.txt)" -cryptokeys="$(realpath crypto.json)" ${compress:+"$compress"} ${encrypt:+"$encrypt"} ${encryptindex:+"$encryptindex"} &
        done
      done
    done
  done
  wait
  rm input.txt
}

if [ $# -eq 0 ]; then
  generate
else
  "$@"
fi
