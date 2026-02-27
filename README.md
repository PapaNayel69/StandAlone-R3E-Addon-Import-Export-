# Addon r3e For Blender

Addon Blender buat import file `*.r3e` effect RF Online (mesh format) dengan referensi material `*.r3m` dan texture `*.r3t`.

## Format
- Struktur chunk `r3e` (CompHeader, Vertex, UV, Face, FaceId, VertexId, MatGroup, Object, Track).
- Decode vertex berdasarkan `vector_data_type` (`0x8000`, `0x4000`, float).
- Decode UV memakai `uv_min/uv_max` dari CompHeader.
- Decode material dari `r3m` (texture id per layer).
- Decode embedded DDS dari `r3t` dengan unlock header XOR password 128-byte.

## Fitur

- `File > Import > RF Online R3E (.r3e)`
  - Import mesh + UV + material group.
  - Topologi import memakai shared-vertex antar poly (poly nempel), UV tetap disimpan per-loop.
  - Auto mapping material `r3m` ke texture `r3t`.
  - Auto load texture dari path disk, atau fallback ke embedded DDS dari `r3t`.
  - Import transform animation (location + quaternion) dari chunk animasi.
  - Menyimpan metadata parser di object (`r3e_parser = cbb_r3e_v2`).

- `File > Export > RF Online R3E (.r3e)`
  - Mode update biner mendukung `common_v1` dan `cbb_r3e_v2`.
  - Untuk parser CBB, addon rebuild chunk mesh (`chunk1`/`2`/`3`/`4`/`5`/`6`/`7`) dari mesh Blender agar hasil re-import sesuai edit.
  - Jika topologi berubah (jumlah vertex/face/UV berubah), exporter tetap bisa menulis file dengan struktur header+chunk baru.

## Cara Install

1. Zip folder `Addon r3e For Blender` (pastikan `__init__.py` di root zip).
2. Blender > `Edit > Preferences > Add-ons > Install...`.
3. Pilih file zip, lalu enable addon `RF Online R3E Import/Export`.

## Cara Pakai Cepat

1. Import `.r3e`.
2. Edit mesh/UV di Blender.
3. Export ke `.r3e` (bisa overwrite file source atau simpan file baru).

## ??

- Hanya mendukung `r3e` mesh dengan magic `113`.
- Sebagian file `*.r3e` lain di client RF (mis. varian non-mesh/encrypted) memang tidak bisa diimport sebagai mesh.
- Jika image texture fisik tidak ada di disk, addon akan coba embedded DDS dari `r3t`; jika dua-duanya tidak ada, material tetap dibuat tanpa texture.
