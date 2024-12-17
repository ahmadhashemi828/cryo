import hashlib
import base58
import os
import struct
import binascii
import bsddb3 as bsddb
from Crypto.Hash import RIPEMD160
from tqdm import tqdm
import time
import zipfile
import rarfile
import py7zr

def tohex(data):
    return data.hex()

def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    h = RIPEMD160.new()
    h.update(data)
    return h.digest()

def pubkeytopubaddress(pubkey):
    digest = sha256(pubkey)
    ripemd = ripemd160(digest)
    prefixed_ripemd = b'\x00' + ripemd
    checksum = sha256(sha256(prefixed_ripemd))[:4]
    address = prefixed_ripemd + checksum
    return base58.b58encode(address)

def hex_padding(s, length):
    return s.zfill(length)

def read_encrypted_key(wallet_filename):
    with open(wallet_filename, "rb") as wallet_file:
        wallet_file.seek(12)
        if wallet_file.read(8) != b"\x62\x31\x05\x00\x09\x00\x00\x00":  # BDB magic, Btree v9
            print("ERROR: file is not a Bitcoin Core wallet")
            return None

    db_env = bsddb.db.DBEnv()
    db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
    db = bsddb.db.DB(db_env)

    try:
        db.open(wallet_filename, "main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
        mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
    finally:
        db.close()
        db_env.close()

    if not mkey:
        raise ValueError("Encrypted master key not found in the Bitcoin Core wallet file")

    encrypted_master_key, salt, method, iter_count = struct.unpack_from("<49p9pII", mkey)

    if method != 0:
        print("warning: unexpected Bitcoin Core key derivation method ", str(method))

    iv = binascii.hexlify(encrypted_master_key[16:32]).decode()
    ct = binascii.hexlify(encrypted_master_key[-16:]).decode()
    iterations = hex_padding('{:x}'.format(iter_count), 8)

    target_mkey = binascii.hexlify(encrypted_master_key).decode() + binascii.hexlify(salt).decode() + iterations
    mkey_encrypted = binascii.hexlify(encrypted_master_key).decode()

    details = {
        "mkey_encrypted": mkey_encrypted,
        "target_mkey": target_mkey,
        "ct": ct,
        "salt": binascii.hexlify(salt).decode(),
        "iv": iv,
        "rawi": iterations,
        "iter": str(int(iterations, 16))
    }

    return details

def read_wallet(file_path):
    mkey_details = read_encrypted_key(file_path)
    if mkey_details:
        return mkey_details
    return None

def find_dat_files(directory):
    dat_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".dat"):
                dat_files.append(os.path.join(root, file))
            elif file.endswith(('.zip', '.rar', '.7z')):
                dat_files.extend(extract_dat_from_archive(os.path.join(root, file)))
    return dat_files

def extract_dat_from_archive(archive_path):
    dat_files = []
    try:
        if archive_path.endswith('.zip'):
            with zipfile.ZipFile(archive_path, 'r') as archive:
                for file in archive.namelist():
                    if file.endswith('.dat'):
                        archive.extract(file, '/tmp')
                        dat_files.append(os.path.join('/tmp', file))
        elif archive_path.endswith('.rar'):
            with rarfile.RarFile(archive_path, 'r') as archive:
                for file in archive.namelist():
                    if file.endswith('.dat'):
                        archive.extract(file, '/tmp')
                        dat_files.append(os.path.join('/tmp', file))
        elif archive_path.endswith('.7z'):
            with py7zr.SevenZipFile(archive_path, 'r') as archive:
                for file in archive.getnames():
                    if file.endswith('.dat'):
                        archive.extract(path='/tmp', targets=[file])
                        dat_files.append(os.path.join('/tmp', file))
    except Exception as e:
        print(f"Error processing archive {archive_path}: {e}")
    return dat_files

def main(output_file):
    current_directory = os.getcwd()
    
    with open(output_file, 'w') as out_file:
        pbar = tqdm(desc="Processing files", unit="file", leave=True)
        for root, dirs, files in os.walk(current_directory):
            for file in files:
                if file.endswith(".dat"):
                    dat_file = os.path.join(root, file)
                    start_time = time.time()
                    try:
                        mkey_details = read_wallet(dat_file)
                        if mkey_details:
                            out_file.write(f"{dat_file}:\n")
                            for key, value in mkey_details.items():
                                out_file.write(f"{key}: {value}\n")
                            out_file.write("\n")
                        current_speed = (time.time() - start_time)
                        pbar.set_postfix({
                            "current_file": dat_file,
                            "current_directory": root,
                            "time_per_file": f"{current_speed:.2f} s/file"
                        })
                    except Exception as e:
                        print(f"Error processing file {dat_file}: {e}")
                    pbar.update(1)
                elif file.endswith(('.zip', '.rar', '.7z')):
                    archive_path = os.path.join(root, file)
                    start_time = time.time()
                    try:
                        dat_files = extract_dat_from_archive(archive_path)
                        for dat_file in dat_files:
                            mkey_details = read_wallet(dat_file)
                            if mkey_details:
                                out_file.write(f"{dat_file}:\n")
                                for key, value in mkey_details.items():
                                    out_file.write(f"{key}: {value}\n")
                                out_file.write("\n")
                            current_speed = (time.time() - start_time)
                            pbar.set_postfix({
                                "current_file": dat_file,
                                "current_directory": root,
                                "time_per_file": f"{current_speed:.2f} s/file"
                            })
                            pbar.update(1)
                    except Exception as e:
                        print(f"Error processing archive {archive_path}: {e}")
                    pbar.update(1)
        pbar.close()

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} output_file")
        sys.exit(0)

    output_file = sys.argv[1]
    main(output_file)
