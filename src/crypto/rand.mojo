# OS-backed CSPRNG only: this module reads from "/dev/urandom" via the Mojo
# stdlib builtin `open`/`FileHandle`, retrying on short reads. It never uses
# `std.random` (a non-cryptographic PRNG) and never links OpenSSL. There is
# no userspace DRBG here -- every byte comes directly from the OS kernel's
# CSPRNG.

from std.collections import List, Span


def fill(dest: Span[mut=True, Byte, _]) raises:
    var target = len(dest)
    if target == 0:
        return

    var source = open("/dev/urandom", "r")
    var filled = 0
    while filled < target:
        var chunk = source.read_bytes(target - filled)
        if len(chunk) == 0:
            source.close()
            raise Error("failed to read OS entropy")
        for i in range(len(chunk)):
            dest[filled + i] = chunk[i]
        filled += len(chunk)
    source.close()


def bytes(length: Int) raises -> List[UInt8]:
    if length < 0:
        raise Error("random byte length must not be negative")
    var out = List[UInt8](length=length, fill=0)
    fill(out[:])
    return out^
