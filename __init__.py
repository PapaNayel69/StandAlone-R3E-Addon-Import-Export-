import os
import re
import struct
import tempfile
import hashlib
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import bpy
from bpy.props import FloatProperty, StringProperty
from bpy_extras.io_utils import ExportHelper, ImportHelper


bl_info = {
    "name": "\x52\x46\x20\x4f\x6e\x6c\x69\x6e\x65\x20\x52\x33\x45\x20\x49\x6d\x70\x6f\x72\x74\x2f\x45\x78\x70\x6f\x72\x74",
    "author": "\x44\x69\x73\x63\x6f\x72\x64\x20\x3d\x20\x50\x61\x70\x61\x4e\x61\x79\x65\x6c",
    "version": (0, 2, 7),
    "blender": (3, 6, 0),
    "location": "\x46\x69\x6c\x65\x20\x3e\x20\x49\x6d\x70\x6f\x72\x74\x2d\x45\x78\x70\x6f\x72\x74",
    "description": "\x49\x6d\x70\x6f\x72\x74\x20\x61\x6e\x64\x20\x75\x70\x64\x61\x74\x65\x20\x52\x46\x20\x4f\x6e\x6c\x69\x6e\x65\x20\x2e\x72\x33\x65\x20\x65\x66\x66\x65\x63\x74\x20\x6d\x65\x73\x68\x20\x77\x69\x74\x68\x20\x2e\x72\x33\x74\x20\x74\x65\x78\x74\x75\x72\x65\x20\x72\x65\x66\x65\x72\x65\x6e\x63\x65\x73",
    "category": "\x49\x6d\x70\x6f\x72\x74\x2d\x45\x78\x70\x6f\x72\x74",
}


R3E_MAGIC = 113
R3E_CHUNK_COUNT = 10
R3E_HEADER_BYTES = 8 + (R3E_CHUNK_COUNT * 8)


@dataclass
class R3EChunk:
    index: int
    offset: int
    size: int


@dataclass
class R3EFile:
    filepath: str
    data: bytearray
    magic: int
    reserved: int
    chunks: List[R3EChunk]


@dataclass
class R3ECommonMesh:
    vertices: List[Tuple[float, float, float]]
    uvs: List[Tuple[float, float]]
    loop_uvs: List[Tuple[float, float]]
    faces: List[List[int]]
    face_material_ids: List[int]
    source_vertex_indices: List[int]
    source_uv_indices: List[int]
    source_vertex_count: int
    source_uv_count: int
    vector_data_type: int
    r3e_position: Tuple[float, float, float]
    r3e_scale: float
    r3e_uv_min: float
    r3e_uv_max: float
    warnings: List[str]


@dataclass
class R3EAnimKey:
    frame: float
    location: Tuple[float, float, float]
    rotation_quaternion: Tuple[float, float, float, float]


@dataclass
class R3MMaterialInfo:
    name: str
    texture_ids: List[int]


_FILE_SEARCH_CACHE: Dict[Tuple[str, str], Optional[str]] = {}
_R3T_EMBED_CACHE: Dict[str, List[str]] = {}

_DDS_UNLOCK_PASSWORD_BYTES = bytes(
    [
        0x2E, 0x80, 0x4D, 0x76, 0x2E, 0xF8, 0xD1, 0xF0, 0xBD, 0x3F, 0x86, 0x81, 0x58, 0x2C, 0x3F, 0x3F,
        0x2E, 0x2E, 0x67, 0x6F, 0x3F, 0x40, 0x3F, 0x78, 0x3C, 0x3F, 0xF1, 0xC0, 0xA5, 0xF6, 0x3B, 0x9F,
        0xC1, 0x20, 0x3F, 0xD7, 0xC8, 0xC1, 0xE9, 0x85, 0x86, 0xBD, 0xEF, 0x56, 0x3F, 0xA1, 0xFB, 0x2E,
        0x87, 0x86, 0x61, 0x4C, 0x21, 0x3B, 0x4E, 0xB4, 0x78, 0x57, 0xAE, 0x97, 0x3F, 0x2E, 0x4A, 0x2E,
        0x3F, 0x4C, 0x2E, 0x44, 0xCD, 0xC5, 0x5F, 0xE8, 0xE9, 0xEC, 0xEB, 0xBD, 0xBE, 0xBB, 0xF7, 0x6C,
        0x2E, 0xF2, 0xE4, 0x2E, 0x3F, 0x3F, 0x97, 0x9F, 0x9D, 0xB3, 0x21, 0xB9, 0x76, 0x65, 0x54, 0x3F,
        0xE6, 0xF6, 0xC6, 0xF0, 0x79, 0xDB, 0xE2, 0xB2, 0x4B, 0x2E, 0x2E, 0xEB, 0xD3, 0xD3, 0xCA, 0xAB,
        0xEA, 0xC7, 0xED, 0x9C, 0xC7, 0xD9, 0xD0, 0x65, 0x48, 0xB4, 0xFA, 0x35, 0x2E, 0x2E, 0x6A, 0x9B,
    ]
)
_DDS_UNLOCK_WORDS = struct.unpack("<32I", _DDS_UNLOCK_PASSWORD_BYTES)


def _read_r3e(filepath: str) -> R3EFile:
    with open(filepath, "rb") as f:
        data = bytearray(f.read())

    if len(data) < R3E_HEADER_BYTES:
        raise ValueError("File terlalu kecil untuk header R3E.")

    magic = struct.unpack_from("<I", data, 0)[0]
    reserved = struct.unpack_from("<I", data, 4)[0]
    chunks: List[R3EChunk] = []
    cursor = 8
    for i in range(R3E_CHUNK_COUNT):
        offset, size = struct.unpack_from("<II", data, cursor)
        chunks.append(R3EChunk(i, int(offset), int(size)))
        cursor += 8

    return R3EFile(
        filepath=os.path.abspath(filepath),
        data=data,
        magic=int(magic),
        reserved=int(reserved),
        chunks=chunks,
    )


def _chunk_bytes(r3e: R3EFile, chunk_index: int) -> bytes:
    chunk = r3e.chunks[chunk_index]
    if chunk.size <= 0:
        return b""
    end = chunk.offset + chunk.size
    if chunk.offset < 0 or end > len(r3e.data):
        raise ValueError(
            f"Chunk {chunk_index} out-of-range (offset={chunk.offset}, size={chunk.size}, file={len(r3e.data)})."
        )
    return bytes(r3e.data[chunk.offset:end])


def _decode_common_mesh(
    r3e: R3EFile, position_scale: float, uv_scale: float
) -> Optional[R3ECommonMesh]:
    warnings: List[str] = []
    if r3e.magic != R3E_MAGIC:
        warnings.append(f"Magic bukan {R3E_MAGIC} (terbaca {r3e.magic}). Tetap coba decode.")

    try:
        comp_chunk = _chunk_bytes(r3e, 0)
        vertex_chunk = _chunk_bytes(r3e, 1)
        uv_chunk = _chunk_bytes(r3e, 3)
        face_chunk = _chunk_bytes(r3e, 4)
        face_id_chunk = _chunk_bytes(r3e, 5)
        vertex_id_chunk = _chunk_bytes(r3e, 6)
        mat_group_chunk = _chunk_bytes(r3e, 7)
    except ValueError:
        return None

    if len(comp_chunk) < 38:
        warnings.append("CompHeader chunk terlalu kecil.")
        return None

    vector_data_type = struct.unpack_from("<H", comp_chunk, 0)[0]
    r3e_pos = struct.unpack_from("<fff", comp_chunk, 14)
    r3e_scale = struct.unpack_from("<f", comp_chunk, 26)[0]
    r3e_uv_min = struct.unpack_from("<f", comp_chunk, 30)[0]
    r3e_uv_max = struct.unpack_from("<f", comp_chunk, 34)[0]
    r3e_uv_scale = (r3e_uv_max - r3e_uv_min) / 2.0
    r3e_uv_pos = r3e_uv_min + r3e_uv_scale

    if vector_data_type == 0x8000:
        raw_vertex_count = len(vertex_chunk) // 3
    elif vector_data_type == 0x4000:
        raw_vertex_count = len(vertex_chunk) // 6
    else:
        raw_vertex_count = len(vertex_chunk) // 12

    if raw_vertex_count <= 0:
        warnings.append("Data vertex kosong.")
        return None

    # Decode vertices using CBB reference logic.
    source_vertices: List[Tuple[float, float, float]] = []
    if vector_data_type == 0x8000:
        for i in range(raw_vertex_count):
            x, y, z = struct.unpack_from("<bbb", vertex_chunk, i * 3)
            vx = ((x / 127.0) * r3e_scale) + r3e_pos[0]
            vy = ((y / 127.0) * r3e_scale) + r3e_pos[1]
            vz = ((z / 127.0) * r3e_scale) + r3e_pos[2]
            # Unity -> Blender axis conversion used by CBB.
            source_vertices.append((vx, vz, vy))
    elif vector_data_type == 0x4000:
        for i in range(raw_vertex_count):
            x, y, z = struct.unpack_from("<hhh", vertex_chunk, i * 6)
            vx = ((x / 32767.0) * r3e_scale) + r3e_pos[0]
            vy = ((y / 32767.0) * r3e_scale) + r3e_pos[1]
            vz = ((z / 32767.0) * r3e_scale) + r3e_pos[2]
            source_vertices.append((vx, vz, vy))
    else:
        for i in range(raw_vertex_count):
            x, y, z = struct.unpack_from("<fff", vertex_chunk, i * 12)
            source_vertices.append((x, z, y))

    source_uvs: List[Tuple[float, float]] = []
    uv_count = len(uv_chunk) // 4
    for i in range(uv_count):
        u, v = struct.unpack_from("<hh", uv_chunk, i * 4)
        uu = ((u / 32767.0) * r3e_uv_scale) + r3e_uv_pos
        vv = 1.0 - (((v / 32767.0) * r3e_uv_scale) + r3e_uv_pos)
        source_uvs.append((uu, vv))

    if len(face_chunk) < 6 or len(face_id_chunk) < 2 or len(vertex_id_chunk) < 2:
        warnings.append("Chunk face/index tidak lengkap.")
        return None

    # Read face structs: ushort vertex_amount + uint vertex_start_id
    face_structs: List[Tuple[int, int]] = []
    for i in range(len(face_chunk) // 6):
        vertex_amount, vertex_start_id = struct.unpack_from("<HI", face_chunk, i * 6)
        face_structs.append((int(vertex_amount), int(vertex_start_id)))

    face_ids = list(
        struct.unpack("<" + ("H" * (len(face_id_chunk) // 2)), face_id_chunk[: (len(face_id_chunk) // 2) * 2])
    )
    vertex_ids = list(
        struct.unpack(
            "<" + ("H" * (len(vertex_id_chunk) // 2)),
            vertex_id_chunk[: (len(vertex_id_chunk) // 2) * 2],
        )
    )

    material_groups: List[Tuple[int, int, int, int]] = []
    if len(mat_group_chunk) >= 22:
        for i in range(len(mat_group_chunk) // 22):
            number_of_faces, starting_face_id, material_id, animated_object_id, *_ = struct.unpack_from(
                "<HIhH3h3h", mat_group_chunk, i * 22
            )
            material_groups.append(
                (int(number_of_faces), int(starting_face_id), int(material_id), int(animated_object_id))
            )

    if not material_groups:
        # Fallback group when MatGroup missing.
        material_groups = [(len(face_ids), 0, 0, 0)]
        warnings.append("MatGroup kosong, fallback single material group.")

    vertices: List[Tuple[float, float, float]] = list(source_vertices)
    uvs: List[Tuple[float, float]] = [(0.0, 0.0)] * len(source_vertices)
    vertex_uv_written: List[bool] = [False] * len(source_vertices)
    loop_uvs: List[Tuple[float, float]] = []
    faces: List[List[int]] = []
    face_material_ids: List[int] = []
    source_vertex_indices: List[int] = []
    source_uv_indices: List[int] = []

    for number_of_faces, starting_face_id, material_id, _animated_object_id in material_groups:
        effective_mat = material_id if material_id >= 0 else 0
        if material_id < 0:
            warnings.append("Ada material_id negatif, fallback ke 0.")

        for i in range(number_of_faces):
            face_id_index = starting_face_id + i
            if face_id_index < 0 or face_id_index >= len(face_ids):
                continue
            face_struct_index = face_ids[face_id_index]
            if face_struct_index < 0 or face_struct_index >= len(face_structs):
                continue

            vertex_amount, vertex_start_id = face_structs[face_struct_index]
            if vertex_amount < 3:
                continue

            out_face: List[int] = []
            loop_uv_start = len(loop_uvs)
            src_vi_start = len(source_vertex_indices)
            src_ui_start = len(source_uv_indices)
            valid_face = True
            for j in range(vertex_amount):
                read_index = vertex_start_id + j
                if read_index < 0 or read_index >= len(vertex_ids) or read_index >= len(source_uvs):
                    valid_face = False
                    break

                source_vertex_index = vertex_ids[read_index]
                if source_vertex_index < 0 or source_vertex_index >= len(source_vertices):
                    valid_face = False
                    break

                uv_value = source_uvs[read_index]
                if not vertex_uv_written[source_vertex_index]:
                    uvs[source_vertex_index] = uv_value
                    vertex_uv_written[source_vertex_index] = True
                loop_uvs.append(uv_value)
                source_vertex_indices.append(source_vertex_index)
                source_uv_indices.append(read_index)
                out_face.append(source_vertex_index)

            if not valid_face or len(set(out_face)) < 3:
                del loop_uvs[loop_uv_start:]
                del source_vertex_indices[src_vi_start:]
                del source_uv_indices[src_ui_start:]
                continue

            faces.append(out_face)
            face_material_ids.append(effective_mat)

    if not faces:
        warnings.append("Tidak ada face yang bisa dibentuk dari data index.")
        return None

    return R3ECommonMesh(
        vertices=vertices,
        uvs=uvs,
        loop_uvs=loop_uvs,
        faces=faces,
        face_material_ids=face_material_ids,
        source_vertex_indices=source_vertex_indices,
        source_uv_indices=source_uv_indices,
        source_vertex_count=len(source_vertices),
        source_uv_count=len(source_uvs),
        vector_data_type=int(vector_data_type),
        r3e_position=(float(r3e_pos[0]), float(r3e_pos[1]), float(r3e_pos[2])),
        r3e_scale=float(r3e_scale),
        r3e_uv_min=float(r3e_uv_min),
        r3e_uv_max=float(r3e_uv_max),
        warnings=warnings,
    )


def _read_fixed_string(raw: bytes, encoding: str = "euc-kr") -> str:
    end = raw.find(b"\x00")
    if end >= 0:
        raw = raw[:end]
    raw = raw.strip()
    if not raw:
        return ""
    try:
        return raw.decode(encoding, errors="ignore").strip()
    except Exception:
        return raw.decode("ascii", errors="ignore").strip()


def _parse_r3m_materials(r3m_path: str) -> List[R3MMaterialInfo]:
    if not os.path.exists(r3m_path):
        return []

    with open(r3m_path, "rb") as f:
        data = f.read()

    if len(data) < 8:
        return []

    cursor = 0
    _version = struct.unpack_from("<f", data, cursor)[0]
    cursor += 4
    material_count = struct.unpack_from("<I", data, cursor)[0]
    cursor += 4

    materials: List[R3MMaterialInfo] = []
    for _ in range(material_count):
        if cursor + 4 + 4 + 4 + 4 + 128 > len(data):
            break

        layer_num = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        _flag = struct.unpack_from("<I", data, cursor)[0]
        cursor += 4
        _detail_surface = struct.unpack_from("<i", data, cursor)[0]
        cursor += 4
        _detail_scale = struct.unpack_from("<f", data, cursor)[0]
        cursor += 4

        name = _read_fixed_string(data[cursor : cursor + 128], encoding="euc-kr")
        cursor += 128

        texture_ids: List[int] = []
        for _layer in range(layer_num):
            if cursor + 46 > len(data):
                cursor = len(data)
                break
            # Layer struct starts with: short iTileAniTexNum, int texture_id, ...
            texture_id = struct.unpack_from("<i", data, cursor + 2)[0]
            if texture_id > 0:
                texture_ids.append(int(texture_id))
            cursor += 46

        materials.append(
            R3MMaterialInfo(
                name=name if name else f"material_{len(materials):03d}",
                texture_ids=texture_ids,
            )
        )

    return materials


def _unlock_dds_header(header: bytes) -> bytes:
    if len(header) != 128:
        return header
    words = list(struct.unpack("<32I", header))
    for i in range(32):
        words[i] ^= _DDS_UNLOCK_WORDS[i]
    return struct.pack("<32I", *words)


def _extract_r3t_texture_paths(r3t_path: str) -> List[str]:
    if not os.path.exists(r3t_path):
        return []

    with open(r3t_path, "rb") as f:
        data = f.read()

    paths: List[str] = []
    seen = set()

    # Structured mode: [float][uint32 texture_count][count * 128-byte path slot]
    if len(data) >= 8:
        try:
            tex_count = struct.unpack_from("<I", data, 4)[0]
        except Exception:
            tex_count = 0

        if 1 <= tex_count <= 64:
            slot_size = 128
            for i in range(tex_count):
                start = 8 + (i * slot_size)
                end_slot = start + slot_size
                if end_slot > len(data):
                    break
                slot = data[start:end_slot]
                raw = _read_fixed_string(slot, encoding="euc-kr")
                if len(raw) < 5:
                    continue
                if ".dds" not in raw.lower():
                    continue
                raw = raw.replace("/", os.sep).replace("\\", os.sep)
                if raw.lower() not in seen:
                    seen.add(raw.lower())
                    paths.append(raw)

    if paths:
        return paths

    # Fallback scan for unknown variants.
    normalized = "".join(chr(b) if 32 <= b <= 126 else "\x00" for b in data)
    candidates = normalized.split("\x00")
    for token in candidates:
        token = token.strip()
        if len(token) < 5:
            continue
        if ".dds" not in token.lower():
            continue
        match = re.search(r"(?i)(.+?\.dds)", token)
        if not match:
            continue
        raw = match.group(1).strip().replace("/", os.sep).replace("\\", os.sep)
        if raw.lower() not in seen:
            seen.add(raw.lower())
            paths.append(raw)

    return paths


def _extract_r3t_embedded_dds(r3t_path: str) -> List[str]:
    key = os.path.abspath(r3t_path).lower()
    if key in _R3T_EMBED_CACHE:
        return _R3T_EMBED_CACHE[key]

    if not os.path.exists(r3t_path):
        _R3T_EMBED_CACHE[key] = []
        return []

    with open(r3t_path, "rb") as f:
        data = f.read()

    if len(data) < 8:
        _R3T_EMBED_CACHE[key] = []
        return []

    try:
        tex_count = struct.unpack_from("<I", data, 4)[0]
    except Exception:
        tex_count = 0

    if tex_count <= 0 or tex_count > 64:
        _R3T_EMBED_CACHE[key] = []
        return []

    pos = 8 + (tex_count * 128)
    out_paths: List[str] = []

    cache_root = os.path.join(tempfile.gettempdir(), "rf_r3e_blender_cache")
    os.makedirs(cache_root, exist_ok=True)

    for block_index in range(tex_count):
        if pos + 4 > len(data):
            out_paths.append("")
            continue

        block_size = struct.unpack_from("<I", data, pos)[0]
        if block_size < 128:
            out_paths.append("")
            pos += 4 + max(0, block_size)
            continue

        header_start = pos + 4
        header_end = header_start + 128
        payload_end = pos + 4 + block_size
        if payload_end > len(data) or header_end > len(data):
            out_paths.append("")
            break

        dds_header = data[header_start:header_end]
        if dds_header[:4] != b"DDS ":
            dds_header = _unlock_dds_header(dds_header)

        texture_data = data[header_end:payload_end]
        dds_bytes = dds_header + texture_data

        digest = hashlib.sha1(
            (key + "|" + str(block_index) + "|" + str(block_size)).encode("utf-8")
        ).hexdigest()[:16]
        filename = f"{os.path.splitext(os.path.basename(r3t_path))[0]}_{block_index:02d}_{digest}.dds"
        out_path = os.path.join(cache_root, filename)
        if not os.path.exists(out_path):
            with open(out_path, "wb") as fw:
                fw.write(dds_bytes)
        out_paths.append(out_path)
        pos = payload_end

    _R3T_EMBED_CACHE[key] = out_paths
    return out_paths


def _find_parent_named(start_path: str, folder_name: str) -> Optional[str]:
    current = os.path.abspath(start_path)
    folder_name = folder_name.lower()
    while True:
        if os.path.basename(current).lower() == folder_name:
            return current
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return None


def _search_file_recursive(root_dir: str, filename: str) -> Optional[str]:
    root_dir = os.path.abspath(root_dir)
    key = (root_dir.lower(), filename.lower())
    if key in _FILE_SEARCH_CACHE:
        return _FILE_SEARCH_CACHE[key]

    if not os.path.isdir(root_dir):
        _FILE_SEARCH_CACHE[key] = None
        return None

    # Fast checks first
    direct = os.path.join(root_dir, filename)
    if os.path.exists(direct):
        _FILE_SEARCH_CACHE[key] = direct
        return direct

    tex_dir = os.path.join(root_dir, "Texture", filename)
    if os.path.exists(tex_dir):
        _FILE_SEARCH_CACHE[key] = tex_dir
        return tex_dir

    result = None
    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for entry in filenames:
            if entry.lower() == filename.lower():
                result = os.path.join(dirpath, entry)
                break
        if result:
            break

    _FILE_SEARCH_CACHE[key] = result
    return result


def _normalize_name_stem(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _levenshtein_distance(a: str, b: str, max_distance: int = 3) -> int:
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        row_min = curr[0]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_val = min(
                prev[j] + 1,      # delete
                curr[j - 1] + 1,  # insert
                prev[j - 1] + cost,  # substitute
            )
            curr.append(curr_val)
            if curr_val < row_min:
                row_min = curr_val
        if row_min > max_distance:
            return max_distance + 1
        prev = curr
    return prev[-1]


def _search_similar_file(root_dir: str, target_filename: str) -> Optional[str]:
    root_dir = os.path.abspath(root_dir)
    if not os.path.isdir(root_dir):
        return None

    target_stem = _normalize_name_stem(os.path.splitext(target_filename)[0])
    if not target_stem:
        return None

    best_path: Optional[str] = None
    best_score = 999

    for dirpath, _dirnames, filenames in os.walk(root_dir):
        for entry in filenames:
            stem, ext = os.path.splitext(entry)
            if ext.lower() not in {".dds", ".png", ".tga", ".bmp", ".jpg", ".jpeg"}:
                continue
            norm = _normalize_name_stem(stem)
            if not norm:
                continue
            dist = _levenshtein_distance(target_stem, norm, max_distance=2)
            if dist <= 2 and dist < best_score:
                best_score = dist
                best_path = os.path.join(dirpath, entry)
                if dist == 0:
                    return best_path

    return best_path


def _resolve_texture_path(raw_path: str, r3e_dir: str, game_root: str) -> Optional[str]:
    normalized = raw_path.replace("/", os.sep).replace("\\", os.sep)
    normalized = normalized.strip().strip('"')
    cleaned = normalized

    if cleaned.startswith("." + os.sep):
        cleaned = cleaned[2:]
    elif cleaned.startswith("." + "/") or cleaned.startswith(".\\"):
        cleaned = cleaned[2:]

    candidates: List[str] = []
    if os.path.isabs(normalized):
        candidates.append(normalized)

    candidates.append(os.path.normpath(os.path.join(r3e_dir, cleaned)))

    # Resolve ".\\item_1\\..." against detected item_1 root from current file path.
    item_root = _find_parent_named(r3e_dir, "item_1")
    if item_root:
        item_parent = os.path.dirname(item_root)
        cleaned_no_item = cleaned
        if cleaned_no_item.lower().startswith("item_1" + os.sep):
            cleaned_no_item = cleaned_no_item[len("item_1" + os.sep) :]
        candidates.append(os.path.normpath(os.path.join(item_parent, cleaned)))
        candidates.append(os.path.normpath(os.path.join(item_root, cleaned_no_item)))

    if game_root:
        candidates.append(os.path.normpath(os.path.join(game_root, cleaned)))
        if item_root and cleaned.lower().startswith("item_1" + os.sep):
            cleaned_no_item = cleaned[len("item_1" + os.sep) :]
            candidates.append(os.path.normpath(os.path.join(game_root, cleaned_no_item)))

    basename = os.path.basename(cleaned)
    stem, _ext = os.path.splitext(basename)
    if basename:
        if game_root:
            candidates.append(os.path.normpath(os.path.join(game_root, "Texture", basename)))
            candidates.append(os.path.normpath(os.path.join(game_root, basename)))
        if item_root:
            candidates.append(os.path.normpath(os.path.join(item_root, basename)))

        # Fallback ext variants if .dds missing but stem exists in another format.
        for ext in (".dds", ".DDS", ".png", ".PNG", ".tga", ".TGA", ".bmp", ".BMP"):
            alt = stem + ext
            if game_root:
                candidates.append(os.path.normpath(os.path.join(game_root, alt)))
                candidates.append(os.path.normpath(os.path.join(game_root, "Texture", alt)))
            if item_root:
                candidates.append(os.path.normpath(os.path.join(item_root, alt)))

    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate

    # Final recursive search by file name.
    if basename:
        search_roots = [r3e_dir]
        if item_root:
            search_roots.append(item_root)
            search_roots.append(os.path.dirname(item_root))
        if game_root:
            search_roots.append(game_root)
        for root in search_roots:
            found = _search_file_recursive(root, basename)
            if found:
                return found
        for ext in (".dds", ".png", ".tga", ".bmp", ".DDS", ".PNG", ".TGA", ".BMP"):
            alt_name = stem + ext
            for root in search_roots:
                found = _search_file_recursive(root, alt_name)
                if found:
                    return found
        # Last chance: tolerate small filename typo in r3t reference.
        for root in search_roots:
            similar = _search_similar_file(root, basename)
            if similar:
                return similar

    return None


def _ensure_material(material_name: str, texture_path: Optional[str]) -> bpy.types.Material:
    material = bpy.data.materials.get(material_name)
    if material is None:
        material = bpy.data.materials.new(material_name)

    if not texture_path:
        return material

    material.use_nodes = True
    nodes = material.node_tree.nodes
    links = material.node_tree.links
    nodes.clear()

    out = nodes.new("ShaderNodeOutputMaterial")
    out.location = (300, 0)
    bsdf = nodes.new("ShaderNodeBsdfPrincipled")
    bsdf.location = (0, 0)
    tex = nodes.new("ShaderNodeTexImage")
    tex.location = (-300, 0)
    links.new(bsdf.outputs["BSDF"], out.inputs["Surface"])
    links.new(tex.outputs["Color"], bsdf.inputs["Base Color"])

    try:
        image = bpy.data.images.load(texture_path, check_existing=True)
        tex.image = image
    except Exception:
        pass

    return material


def _quat_normalize(q: Tuple[float, float, float, float]) -> Tuple[float, float, float, float]:
    w, x, y, z = q
    norm = (w * w) + (x * x) + (y * y) + (z * z)
    if norm <= 1.0e-12:
        return (1.0, 0.0, 0.0, 0.0)
    inv = norm ** -0.5
    return (w * inv, x * inv, y * inv, z * inv)


def _quat_conjugate(q: Tuple[float, float, float, float]) -> Tuple[float, float, float, float]:
    w, x, y, z = q
    return (w, -x, -y, -z)


def _quat_mul(
    a: Tuple[float, float, float, float], b: Tuple[float, float, float, float]
) -> Tuple[float, float, float, float]:
    aw, ax, ay, az = a
    bw, bx, by, bz = b
    return (
        aw * bw - ax * bx - ay * by - az * bz,
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
    )


def _parse_transform_animation(r3e: R3EFile) -> Tuple[List[R3EAnimKey], List[str]]:
    warnings: List[str] = []
    try:
        chunk8 = _chunk_bytes(r3e, 8)
        chunk9 = _chunk_bytes(r3e, 9)
    except ValueError:
        return [], ["Chunk animasi tidak valid."]

    if len(chunk8) < 88 or len(chunk9) < 68:
        return [], warnings

    # chunk8 usually contains N descriptors, each 22 uint32.
    if len(chunk8) % 88 != 0:
        warnings.append("Ukuran chunk descriptor animasi tidak kelipatan 88 bytes.")
        return [], warnings

    desc_count = len(chunk8) // 88
    if desc_count <= 0:
        return [], warnings

    selected = None
    for d in range(desc_count):
        base = d * 88
        w = struct.unpack_from("<" + ("I" * 22), chunk8, base)
        frame_count = int(w[2]) if 1 <= int(w[2]) <= 10000 else 0
        if frame_count <= 1:
            continue
        pos_off = int(w[19])
        rot_off = int(w[20])
        aux_off = int(w[21])
        pos_len = frame_count * 16
        rot_len = frame_count * 20
        aux_len = frame_count * 32
        if (
            pos_off >= 0
            and rot_off >= 0
            and aux_off >= 0
            and pos_off + pos_len <= len(chunk9)
            and rot_off + rot_len <= len(chunk9)
            and aux_off + aux_len <= len(chunk9)
        ):
            selected = (w, frame_count, pos_off, rot_off, aux_off, d)
            break

    if selected is None:
        warnings.append("Tidak menemukan descriptor animasi transform valid.")
        return [], warnings

    w, frame_count, section_a, section_b, section_c, desc_index = selected
    if desc_count > 1:
        warnings.append(f"Terdeteksi {desc_count} descriptor animasi; importer memakai descriptor #{desc_index}.")

    keys: List[R3EAnimKey] = []
    for i in range(frame_count):
        ta, px, py, pz = struct.unpack_from("<ffff", chunk9, section_a + (i * 16))
        tb, qx, qy, qz, qw = struct.unpack_from("<fffff", chunk9, section_b + (i * 20))
        _tc, _sx, _sy, _sz, _cx, _cy, _cz, _cw = struct.unpack_from("<ffffffff", chunk9, section_c + (i * 32))

        frame = float(i)
        if abs(ta - i) <= 0.01:
            frame = float(ta)
        elif abs(tb - i) <= 0.01:
            frame = float(tb)

        norm = (qw * qw) + (qx * qx) + (qy * qy) + (qz * qz)
        if norm > 1.0e-12:
            inv = norm ** -0.5
            quat = (qw * inv, qx * inv, qy * inv, qz * inv)
        else:
            quat = (1.0, 0.0, 0.0, 0.0)

        keys.append(
            R3EAnimKey(
                frame=frame,
                location=(float(px), float(py), float(pz)),
                rotation_quaternion=quat,
            )
        )

    return keys, warnings


def _apply_transform_animation(
    obj: bpy.types.Object, keys: List[R3EAnimKey], context: bpy.types.Context
) -> None:
    if not keys:
        return

    obj.animation_data_clear()
    obj.rotation_mode = "QUATERNION"

    base_loc = keys[0].location
    # Base orientation correction so first keyed pose stands upright in Blender.
    # Quaternion (w,x,y,z) for -90 deg around local X.
    local_fix = (0.7071067811865476, -0.7071067811865476, 0.0, 0.0)
    # Remap RF spin axis to Blender Z so animation rotates flat on ground plane.
    # Quaternion for -90 deg around X.
    axis_remap = (0.7071067811865476, -0.7071067811865476, 0.0, 0.0)
    axis_remap_inv = _quat_conjugate(axis_remap)

    for key in keys:
        frame = key.frame + 1.0
        loc = (
            key.location[0] - base_loc[0],
            key.location[1] - base_loc[1],
            key.location[2] - base_loc[2],
        )
        # Keep absolute quaternion from file so base orientation is preserved.
        rot_abs = _quat_normalize(key.rotation_quaternion)
        rot_abs = _quat_normalize(_quat_mul(_quat_mul(axis_remap, rot_abs), axis_remap_inv))
        rot_abs = _quat_normalize(_quat_mul(rot_abs, local_fix))

        obj.location = loc
        obj.rotation_quaternion = rot_abs
        obj.keyframe_insert(data_path="location", frame=frame)
        obj.keyframe_insert(data_path="rotation_quaternion", frame=frame)

    if obj.animation_data and obj.animation_data.action:
        for fcurve in obj.animation_data.action.fcurves:
            for kp in fcurve.keyframe_points:
                kp.interpolation = "LINEAR"

    frame_end = int(max(key.frame for key in keys) + 1.0)
    if context.scene.frame_end < frame_end:
        context.scene.frame_end = frame_end


def _clamp_int(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return int(value)


def _collect_vertex_uvs(mesh: bpy.types.Mesh, default_uvs: List[Tuple[float, float]]) -> List[Tuple[float, float]]:
    vertex_uvs: List[Tuple[float, float]] = list(default_uvs)
    if len(vertex_uvs) < len(mesh.vertices):
        vertex_uvs.extend([(0.0, 0.0)] * (len(mesh.vertices) - len(vertex_uvs)))
    if len(vertex_uvs) > len(mesh.vertices):
        vertex_uvs = vertex_uvs[: len(mesh.vertices)]

    uv_layer = mesh.uv_layers.active
    if not uv_layer:
        return vertex_uvs

    accum_u = [0.0] * len(mesh.vertices)
    accum_v = [0.0] * len(mesh.vertices)
    accum_n = [0] * len(mesh.vertices)

    for loop in mesh.loops:
        vid = int(loop.vertex_index)
        if vid < 0 or vid >= len(mesh.vertices):
            continue
        uv = uv_layer.data[loop.index].uv
        accum_u[vid] += float(uv.x)
        accum_v[vid] += float(uv.y)
        accum_n[vid] += 1

    for i in range(len(mesh.vertices)):
        if accum_n[i] > 0:
            vertex_uvs[i] = (accum_u[i] / accum_n[i], accum_v[i] / accum_n[i])

    return vertex_uvs


def _assemble_r3e_with_chunks(r3e: R3EFile, chunks: List[bytes]) -> bytearray:
    if len(chunks) != R3E_CHUNK_COUNT:
        raise ValueError(f"Jumlah chunk invalid ({len(chunks)}), expected {R3E_CHUNK_COUNT}.")

    out_data = bytearray(R3E_HEADER_BYTES)
    struct.pack_into("<I", out_data, 0, int(r3e.magic))
    struct.pack_into("<I", out_data, 4, int(r3e.reserved))

    cursor = R3E_HEADER_BYTES
    for i, payload in enumerate(chunks):
        payload = bytes(payload)
        struct.pack_into("<II", out_data, 8 + (i * 8), int(cursor), int(len(payload)))
        out_data.extend(payload)
        cursor += len(payload)

    return out_data


def _build_matgroup_anim_map(r3e: R3EFile) -> Dict[int, int]:
    out: Dict[int, int] = {}
    mat_group_chunk = _chunk_bytes(r3e, 7)
    for i in range(len(mat_group_chunk) // 22):
        _num_faces, _start_face, material_id, animated_object_id, *_ = struct.unpack_from(
            "<HIhH3h3h", mat_group_chunk, i * 22
        )
        out[int(material_id)] = int(animated_object_id)
    return out


def _weld_vertices_by_position(
    mesh: bpy.types.Mesh, epsilon: float = 1.0e-5
) -> Tuple[List[Tuple[float, float, float]], List[int]]:
    if len(mesh.vertices) <= 0:
        return [], []

    inv_eps = 1.0 / max(epsilon, 1.0e-9)
    welded_positions: List[Tuple[float, float, float]] = []
    old_to_new: List[int] = [0] * len(mesh.vertices)
    buckets: Dict[Tuple[int, int, int], List[int]] = {}

    for i, v in enumerate(mesh.vertices):
        x = float(v.co.x)
        y = float(v.co.y)
        z = float(v.co.z)
        key = (int(round(x * inv_eps)), int(round(y * inv_eps)), int(round(z * inv_eps)))

        found = -1
        for idx in buckets.get(key, []):
            wx, wy, wz = welded_positions[idx]
            if abs(wx - x) <= epsilon and abs(wy - y) <= epsilon and abs(wz - z) <= epsilon:
                found = idx
                break

        if found < 0:
            found = len(welded_positions)
            welded_positions.append((x, y, z))
            buckets.setdefault(key, []).append(found)

        old_to_new[i] = found

    return welded_positions, old_to_new


def _export_update_cbb(
    mesh: bpy.types.Mesh,
    mesh_data: R3ECommonMesh,
    r3e: R3EFile,
    export_notes: Optional[List[str]] = None,
) -> Tuple[bytearray, int, int]:
    if export_notes is None:
        export_notes = []

    mesh_vertex_count = len(mesh.vertices)
    mesh_face_count = len(mesh.polygons)
    mesh_loop_count = len(mesh.loops)
    if mesh_vertex_count <= 0:
        raise ValueError("Object mesh kosong, tidak bisa export.")
    if mesh_face_count <= 0 or mesh_loop_count <= 0:
        raise ValueError("Object mesh tidak punya face, tidak bisa export.")
    if mesh_vertex_count > 65535:
        raise ValueError(f"Vertex terlalu banyak ({mesh_vertex_count}), format R3E hanya mendukung <= 65535.")

    welded_positions, old_to_new_vertex = _weld_vertices_by_position(mesh, epsilon=1.0e-5)
    if not welded_positions:
        raise ValueError("Gagal membentuk vertex welded untuk export.")
    if len(welded_positions) > 65535:
        raise ValueError(
            f"Vertex welded terlalu banyak ({len(welded_positions)}), format R3E hanya mendukung <= 65535."
        )
    if len(welded_positions) < mesh_vertex_count:
        export_notes.append(
            f"Auto-weld vertex aktif: {mesh_vertex_count} -> {len(welded_positions)} (poly jadi nempel)."
        )

    vector_data_type = int(mesh_data.vector_data_type)
    if vector_data_type not in (0x8000, 0x4000):
        vector_data_type = 0
        export_notes.append("Vector type source tidak kompresi, exporter tulis posisi float32.")

    # Build RF-space vertices: Blender (x,y,z) -> RF axes (x, y=z, z=y).
    rf_positions: List[Tuple[float, float, float]] = []
    for bx, by, bz in welded_positions:
        rf_positions.append((bx, bz, by))

    pos_x = mesh_data.r3e_position[0]
    pos_y = mesh_data.r3e_position[1]
    pos_z = mesh_data.r3e_position[2]
    pos_scale = mesh_data.r3e_scale if abs(mesh_data.r3e_scale) > 1.0e-8 else 1.0

    if vector_data_type in (0x8000, 0x4000):
        min_x = min(p[0] for p in rf_positions)
        max_x = max(p[0] for p in rf_positions)
        min_y = min(p[1] for p in rf_positions)
        max_y = max(p[1] for p in rf_positions)
        min_z = min(p[2] for p in rf_positions)
        max_z = max(p[2] for p in rf_positions)

        pos_x = (min_x + max_x) * 0.5
        pos_y = (min_y + max_y) * 0.5
        pos_z = (min_z + max_z) * 0.5
        pos_scale = max(
            max(abs(min_x - pos_x), abs(max_x - pos_x)),
            max(abs(min_y - pos_y), abs(max_y - pos_y)),
            max(abs(min_z - pos_z), abs(max_z - pos_z)),
            1.0e-6,
        )

    vertex_chunk = bytearray()
    if vector_data_type == 0x8000:
        for fx, fy, fz in rf_positions:
            rx = _clamp_int(int(round(((fx - pos_x) / pos_scale) * 127.0)), -127, 127)
            ry = _clamp_int(int(round(((fy - pos_y) / pos_scale) * 127.0)), -127, 127)
            rz = _clamp_int(int(round(((fz - pos_z) / pos_scale) * 127.0)), -127, 127)
            vertex_chunk.extend(struct.pack("<bbb", rx, ry, rz))
    elif vector_data_type == 0x4000:
        for fx, fy, fz in rf_positions:
            rx = _clamp_int(int(round(((fx - pos_x) / pos_scale) * 32767.0)), -32767, 32767)
            ry = _clamp_int(int(round(((fy - pos_y) / pos_scale) * 32767.0)), -32767, 32767)
            rz = _clamp_int(int(round(((fz - pos_z) / pos_scale) * 32767.0)), -32767, 32767)
            vertex_chunk.extend(struct.pack("<hhh", rx, ry, rz))
    else:
        for fx, fy, fz in rf_positions:
            vertex_chunk.extend(struct.pack("<fff", float(fx), float(fy), float(fz)))

    # VColor chunk follows exported vertex count.
    old_vcolor = _chunk_bytes(r3e, 2)
    default_color = struct.unpack_from("<I", old_vcolor, 0)[0] if len(old_vcolor) >= 4 else 0xFFFFFFFF
    vcolor_chunk = bytearray()
    for _ in range(len(welded_positions)):
        vcolor_chunk.extend(struct.pack("<I", int(default_color)))

    uv_layer = mesh.uv_layers.active
    uv_raw_values: List[Tuple[float, float]] = []
    uv_range_values: List[float] = []
    if uv_layer:
        for loop in mesh.loops:
            uv = uv_layer.data[loop.index].uv
            u_raw = float(uv.x)
            v_raw = 1.0 - float(uv.y)
            uv_raw_values.append((u_raw, v_raw))
            uv_range_values.append(u_raw)
            uv_range_values.append(v_raw)
    else:
        uv_raw_values = [(0.0, 1.0)] * mesh_loop_count
        uv_range_values = [0.0, 1.0]
        export_notes.append("UV layer tidak ditemukan, exporter isi UV default.")

    uv_min = min(uv_range_values)
    uv_max = max(uv_range_values)
    if abs(uv_max - uv_min) <= 1.0e-8:
        uv_min = uv_min - 0.5
        uv_max = uv_max + 0.5
    uv_half_range = (uv_max - uv_min) * 0.5
    uv_center = uv_min + uv_half_range

    uv_chunk = bytearray()
    for u_raw, v_raw in uv_raw_values:
        ru = _clamp_int(int(round(((u_raw - uv_center) / uv_half_range) * 32767.0)), -32767, 32767)
        rv = _clamp_int(int(round(((v_raw - uv_center) / uv_half_range) * 32767.0)), -32767, 32767)
        uv_chunk.extend(struct.pack("<hh", ru, rv))

    face_structs: List[Tuple[int, int]] = []
    face_ids: List[int] = []
    vertex_ids: List[int] = []
    face_materials: List[int] = []

    for poly in mesh.polygons:
        v_amount = int(poly.loop_total)
        if v_amount < 3:
            continue
        if v_amount > 65535:
            raise ValueError(f"Face punya vertex terlalu banyak ({v_amount}), batas format 65535.")
        v_start = len(vertex_ids)
        for i in range(poly.loop_start, poly.loop_start + poly.loop_total):
            vid = int(mesh.loops[i].vertex_index)
            if vid < 0 or vid >= len(old_to_new_vertex):
                raise ValueError(f"Vertex index loop invalid: {vid}")
            vid = int(old_to_new_vertex[vid])
            if vid < 0 or vid > 65535:
                raise ValueError(f"Vertex index out-of-range untuk format ushort: {vid}")
            vertex_ids.append(vid)
        face_structs.append((v_amount, v_start))
        face_ids.append(len(face_structs) - 1)
        face_materials.append(int(poly.material_index))

    if not face_structs:
        raise ValueError("Tidak ada face valid untuk ditulis ke R3E.")
    if len(face_structs) > 65535:
        raise ValueError(f"Jumlah face terlalu banyak ({len(face_structs)}), batas format 65535.")

    face_chunk = bytearray()
    for v_amount, v_start in face_structs:
        face_chunk.extend(struct.pack("<HI", int(v_amount), int(v_start)))

    face_id_chunk = bytearray()
    for fid in face_ids:
        face_id_chunk.extend(struct.pack("<H", int(fid)))

    vertex_id_chunk = bytearray()
    for vid in vertex_ids:
        vertex_id_chunk.extend(struct.pack("<H", int(vid)))

    mat_anim_map = _build_matgroup_anim_map(r3e)
    groups: List[Tuple[int, int, int, int]] = []
    for face_index, mat_id in enumerate(face_materials):
        if mat_id < -32768 or mat_id > 32767:
            mat_id = 0
        if groups and groups[-1][2] == mat_id:
            num_faces, start_face, material_id, anim_id = groups[-1]
            groups[-1] = (num_faces + 1, start_face, material_id, anim_id)
        else:
            groups.append((1, face_index, mat_id, int(mat_anim_map.get(mat_id, 0))))

    mat_group_chunk = bytearray()
    for num_faces, start_face, material_id, anim_id in groups:
        mat_group_chunk.extend(
            struct.pack(
                "<HIhH3h3h",
                int(num_faces),
                int(start_face),
                int(material_id),
                int(anim_id),
                0,
                0,
                0,
                0,
                0,
                0,
            )
        )

    comp_chunk = bytearray(_chunk_bytes(r3e, 0))
    if len(comp_chunk) < 38:
        raise ValueError("CompHeader chunk terlalu kecil, tidak bisa ditulis.")

    struct.pack_into("<H", comp_chunk, 0, int(mesh_data.vector_data_type))
    struct.pack_into("<fff", comp_chunk, 14, float(pos_x), float(pos_y), float(pos_z))
    struct.pack_into("<f", comp_chunk, 26, float(pos_scale))
    struct.pack_into("<f", comp_chunk, 30, float(uv_min))
    struct.pack_into("<f", comp_chunk, 34, float(uv_max))

    final_chunks = [
        bytes(comp_chunk),
        bytes(vertex_chunk),
        bytes(vcolor_chunk),
        bytes(uv_chunk),
        bytes(face_chunk),
        bytes(face_id_chunk),
        bytes(vertex_id_chunk),
        bytes(mat_group_chunk),
        _chunk_bytes(r3e, 8),
        _chunk_bytes(r3e, 9),
    ]

    if mesh_vertex_count != int(mesh_data.source_vertex_count) or mesh_loop_count != int(mesh_data.source_uv_count):
        export_notes.append(
            "Topology berubah, exporter rebuild chunk mesh (vertex/uv/face/index/material group) agar hasil import sesuai edit."
        )

    out_data = _assemble_r3e_with_chunks(r3e, final_chunks)
    return out_data, mesh_vertex_count, mesh_loop_count


class IMPORT_OT_rf_r3e(bpy.types.Operator, ImportHelper):
    bl_idname = "import_scene.rf_r3e"
    bl_label = "Import RF R3E"
    bl_options = {"REGISTER", "UNDO"}

    filename_ext = ".r3e"
    filter_glob: StringProperty(default="*.r3e", options={"HIDDEN"})

    game_root: StringProperty(
        name="Game Root (Opsional)",
        subtype="DIR_PATH",
        default="",
        description="Path root client RF Online untuk resolve texture .dds dari .r3t",
    )

    position_scale: FloatProperty(
        name="Position Scale",
        default=32767.0,
        min=1.0,
        description="Pembagi int16 posisi -> float Blender",
    )

    uv_scale: FloatProperty(
        name="UV Scale",
        default=32767.0,
        min=1.0,
        description="Pembagi int16 UV -> float Blender",
    )

    def execute(self, context):
        try:
            r3e = _read_r3e(self.filepath)
        except Exception as ex:
            self.report({"ERROR"}, f"Gagal baca R3E: {ex}")
            return {"CANCELLED"}

        if r3e.magic != R3E_MAGIC:
            magic_hex = f"0x{int(r3e.magic):08X}"
            self.report(
                {"ERROR"},
                f"R3E magic tidak didukung ({r3e.magic} / {magic_hex}). File ini kemungkinan varian effect non-mesh/encrypted.",
            )
            return {"CANCELLED"}

        mesh_data = _decode_common_mesh(r3e, self.position_scale, self.uv_scale)
        if mesh_data is None:
            self.report({"ERROR"}, "Format R3E varian ini belum bisa didecode sebagai mesh umum.")
            return {"CANCELLED"}

        object_name = os.path.splitext(os.path.basename(self.filepath))[0]
        mesh = bpy.data.meshes.new(object_name)
        mesh.from_pydata(mesh_data.vertices, [], mesh_data.faces)
        mesh.update()
        mesh.validate(verbose=False)

        obj = bpy.data.objects.new(object_name, mesh)
        context.collection.objects.link(obj)
        context.view_layer.objects.active = obj
        obj.select_set(True)

        # UV per-loop (preserve seams without splitting topology).
        if mesh.uv_layers:
            uv_layer = mesh.uv_layers.active
        else:
            uv_layer = mesh.uv_layers.new(name="UVMap")
        if uv_layer:
            for loop in mesh.loops:
                if 0 <= loop.index < len(mesh_data.loop_uvs):
                    uv_layer.data[loop.index].uv = mesh_data.loop_uvs[loop.index]
                else:
                    vid = loop.vertex_index
                    if 0 <= vid < len(mesh_data.uvs):
                        uv_layer.data[loop.index].uv = mesh_data.uvs[vid]
                    else:
                        uv_layer.data[loop.index].uv = (0.0, 0.0)

        # Materials from .r3t
        r3e_dir = os.path.dirname(os.path.abspath(self.filepath))
        base = os.path.splitext(os.path.basename(self.filepath))[0]
        r3t_path = os.path.join(r3e_dir, base + ".r3t")
        r3m_path = os.path.join(r3e_dir, base + ".r3m")
        import_warnings: List[str] = []

        try:
            r3m_materials = _parse_r3m_materials(r3m_path)
        except Exception as ex:
            r3m_materials = []
            import_warnings.append(f"R3M parse gagal ({ex})")

        try:
            texture_refs = _extract_r3t_texture_paths(r3t_path)
        except Exception as ex:
            texture_refs = []
            import_warnings.append(f"R3T path parse gagal ({ex})")

        try:
            embedded_dds = _extract_r3t_embedded_dds(r3t_path)
        except Exception as ex:
            embedded_dds = []
            import_warnings.append(f"R3T embedded parse gagal ({ex})")

        missing_textures: List[str] = []

        materials: List[bpy.types.Material] = []
        if r3m_materials:
            for material_id, mat_info in enumerate(r3m_materials):
                raw_tex: Optional[str] = None
                resolved: Optional[str] = None
                texture_id: Optional[int] = mat_info.texture_ids[0] if mat_info.texture_ids else None

                if texture_id and 1 <= texture_id <= len(texture_refs):
                    raw_tex = texture_refs[texture_id - 1]
                    resolved = _resolve_texture_path(raw_tex, r3e_dir, self.game_root)

                if (not resolved) and texture_id and 1 <= texture_id <= len(embedded_dds):
                    embed_path = embedded_dds[texture_id - 1]
                    if embed_path and os.path.exists(embed_path):
                        resolved = embed_path

                # Fallback by material order when texture id absent/invalid.
                if not raw_tex and material_id < len(texture_refs):
                    raw_tex = texture_refs[material_id]
                    resolved = _resolve_texture_path(raw_tex, r3e_dir, self.game_root)
                if (not resolved) and material_id < len(embedded_dds):
                    embed_path = embedded_dds[material_id]
                    if embed_path and os.path.exists(embed_path):
                        resolved = embed_path

                mat_name = mat_info.name if mat_info.name else f"{object_name}_mat_{material_id:02d}"
                material = _ensure_material(mat_name, resolved)
                material["r3m_material_id"] = material_id
                if texture_id:
                    material["r3m_texture_id"] = texture_id
                if raw_tex:
                    material["r3t_texture_ref"] = raw_tex
                if resolved:
                    material["resolved_texture"] = resolved
                elif raw_tex:
                    missing_textures.append(raw_tex)

                mesh.materials.append(material)
                materials.append(material)
        elif texture_refs:
            for i, raw_tex in enumerate(texture_refs):
                resolved = _resolve_texture_path(raw_tex, r3e_dir, self.game_root)
                if not resolved and i < len(embedded_dds):
                    embed_path = embedded_dds[i]
                    if embed_path and os.path.exists(embed_path):
                        resolved = embed_path
                mat_name = f"{object_name}_mat_{i:02d}"
                material = _ensure_material(mat_name, resolved)
                material["r3t_texture_ref"] = raw_tex
                if resolved:
                    material["resolved_texture"] = resolved
                else:
                    missing_textures.append(raw_tex)
                mesh.materials.append(material)
                materials.append(material)
        elif embedded_dds:
            for i, embed_path in enumerate(embedded_dds):
                if not embed_path:
                    continue
                mat_name = f"{object_name}_mat_{i:02d}"
                material = _ensure_material(mat_name, embed_path)
                material["resolved_texture"] = embed_path
                mesh.materials.append(material)
                materials.append(material)
        if not materials:
            material = _ensure_material(f"{object_name}_mat_00", None)
            mesh.materials.append(material)
            materials.append(material)

        if materials:
            material_count = len(materials)
            for poly_index, poly in enumerate(mesh.polygons):
                raw_mat = 0
                if poly_index < len(mesh_data.face_material_ids):
                    raw_mat = mesh_data.face_material_ids[poly_index]
                if 0 <= raw_mat < material_count:
                    poly.material_index = raw_mat
                else:
                    poly.material_index = abs(raw_mat) % material_count

        anim_keys, anim_warnings = _parse_transform_animation(r3e)
        if anim_keys:
            _apply_transform_animation(obj, anim_keys, context)

        # Save metadata for exporter
        obj["r3e_source"] = os.path.abspath(self.filepath)
        obj["r3e_position_scale"] = float(self.position_scale)
        obj["r3e_uv_scale"] = float(self.uv_scale)
        obj["r3e_parser"] = "cbb_r3e_v2"
        obj["r3e_vertex_count"] = len(mesh_data.vertices)
        obj["r3e_face_count"] = len(mesh_data.faces)
        obj["r3e_anim_keys"] = len(anim_keys)

        info = f"Import selesai: {len(mesh_data.vertices)} vertices, {len(mesh_data.faces)} faces."
        if texture_refs:
            loaded_count = len(texture_refs) - len(missing_textures)
            info += f" Texture loaded {loaded_count}/{len(texture_refs)}."
            if embedded_dds:
                info += f" Embedded DDS: {len(embedded_dds)}."
        if anim_keys:
            info += f" Anim keyframes: {len(anim_keys)}."
        else:
            info += " Animasi transform tidak terdeteksi."
        if mesh_data.warnings:
            info = info + " Warning: " + "; ".join(mesh_data.warnings[:3])
        if anim_warnings:
            info = info + " Anim: " + "; ".join(anim_warnings[:2])
        if missing_textures:
            miss_preview = "; ".join(missing_textures[:2])
            info = info + f" Missing texture refs: {miss_preview}"
        if import_warnings:
            info = info + " Import: " + "; ".join(import_warnings[:2])
        self.report({"INFO"}, info)
        return {"FINISHED"}


class EXPORT_OT_rf_r3e(bpy.types.Operator, ExportHelper):
    bl_idname = "export_scene.rf_r3e"
    bl_label = "Export RF R3E (Update)"
    bl_options = {"REGISTER"}

    filename_ext = ".r3e"
    filter_glob: StringProperty(default="*.r3e", options={"HIDDEN"})

    position_scale: FloatProperty(
        name="Position Scale",
        default=32767.0,
        min=1.0,
        description="Pengali float Blender -> int16 posisi",
    )

    uv_scale: FloatProperty(
        name="UV Scale",
        default=32767.0,
        min=1.0,
        description="Pengali float Blender -> int16 UV",
    )

    def invoke(self, context, event):
        obj = context.active_object
        if obj and "r3e_source" in obj:
            src = obj.get("r3e_source")
            if isinstance(src, str) and src:
                self.filepath = src
                if "r3e_position_scale" in obj:
                    try:
                        self.position_scale = float(obj["r3e_position_scale"])
                    except Exception:
                        pass
                if "r3e_uv_scale" in obj:
                    try:
                        self.uv_scale = float(obj["r3e_uv_scale"])
                    except Exception:
                        pass
        return super().invoke(context, event)

    def execute(self, context):
        obj = context.active_object
        if obj is None or obj.type != "MESH":
            self.report({"ERROR"}, "Pilih object mesh hasil import R3E terlebih dulu.")
            return {"CANCELLED"}

        parser_tag = str(obj.get("r3e_parser", ""))
        if not parser_tag:
            parser_tag = "common_v1"

        source_path = obj.get("r3e_source")
        if not source_path or not os.path.exists(source_path):
            self.report(
                {"ERROR"},
                "Metadata source R3E tidak ditemukan. Export update butuh file source untuk menjaga struktur chunk.",
            )
            return {"CANCELLED"}

        try:
            r3e = _read_r3e(source_path)
        except Exception as ex:
            self.report({"ERROR"}, f"Gagal baca source R3E: {ex}")
            return {"CANCELLED"}

        mesh_data = _decode_common_mesh(r3e, self.position_scale, self.uv_scale)
        if mesh_data is None:
            self.report({"ERROR"}, "Format source R3E tidak cocok untuk mode update.")
            return {"CANCELLED"}

        if obj.mode == "EDIT":
            obj.update_from_editmode()
        mesh = obj.data
        out_data = bytearray(r3e.data)
        export_notes: List[str] = []
        try:
            if parser_tag == "cbb_r3e_v2":
                out_data, written_vertices, written_uvs = _export_update_cbb(
                    mesh, mesh_data, r3e, export_notes=export_notes
                )
            else:
                vertex_count = len(mesh_data.vertices)
                if len(mesh.vertices) < vertex_count:
                    self.report(
                        {"ERROR"},
                        f"Vertex object ({len(mesh.vertices)}) lebih sedikit dari vertex source ({vertex_count}).",
                    )
                    return {"CANCELLED"}

                pos_chunk = r3e.chunks[1]
                uv_chunk = r3e.chunks[2]

                # Legacy writer (common_v1): int16 xyz + int16 uv.
                written_vertices = min(vertex_count, pos_chunk.size // 6)
                for i in range(written_vertices):
                    co = mesh.vertices[i].co
                    sx = _clamp_int(int(round(float(co.x) * self.position_scale)), -32768, 32767)
                    sy = _clamp_int(int(round(float(co.y) * self.position_scale)), -32768, 32767)
                    sz = _clamp_int(int(round(float(co.z) * self.position_scale)), -32768, 32767)
                    struct.pack_into("<hhh", out_data, pos_chunk.offset + i * 6, sx, sy, sz)

                vertex_uvs = _collect_vertex_uvs(mesh, [(0.0, 0.0)] * len(mesh.vertices))
                written_uvs = min(vertex_count, uv_chunk.size // 4)
                for i in range(written_uvs):
                    u, v = vertex_uvs[i]
                    su = _clamp_int(int(round(float(u) * self.uv_scale)), -32768, 32767)
                    sv = _clamp_int(int(round(float(v) * self.uv_scale)), -32768, 32767)
                    struct.pack_into("<hh", out_data, uv_chunk.offset + i * 4, su, sv)
        except Exception as ex:
            self.report({"ERROR"}, f"Gagal update data mesh ke R3E: {ex}")
            return {"CANCELLED"}

        out_path = os.path.abspath(self.filepath)
        try:
            with open(out_path, "wb") as f:
                f.write(out_data)
        except Exception as ex:
            self.report({"ERROR"}, f"Gagal menulis file output: {ex}")
            return {"CANCELLED"}

        info = f"Export update selesai: {out_path} (parser={parser_tag}, vertices={written_vertices}, uvs={written_uvs})"
        if export_notes:
            info += " Note: " + "; ".join(export_notes[:2])
        self.report({"INFO"}, info)
        return {"FINISHED"}


def menu_import(self, _context):
    self.layout.operator(IMPORT_OT_rf_r3e.bl_idname, text="RF Online R3E (.r3e)")


def menu_export(self, _context):
    self.layout.operator(EXPORT_OT_rf_r3e.bl_idname, text="RF Online R3E (.r3e)")


classes = (
    IMPORT_OT_rf_r3e,
    EXPORT_OT_rf_r3e,
)


def register():
    for cls in classes:
        bpy.utils.register_class(cls)
    bpy.types.TOPBAR_MT_file_import.append(menu_import)
    bpy.types.TOPBAR_MT_file_export.append(menu_export)


def unregister():
    bpy.types.TOPBAR_MT_file_export.remove(menu_export)
    bpy.types.TOPBAR_MT_file_import.remove(menu_import)
    for cls in reversed(classes):
        bpy.utils.unregister_class(cls)


if __name__ == "__main__":
    register()
