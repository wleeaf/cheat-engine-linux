"""Restrict real QEMU to g/G while forwarding its actual CPU state unchanged."""


class WholeRegisterProxy:
    def __init__(self, to_guest, to_client, frame):
        self.to_guest = to_guest
        self.to_client = to_client
        self.frame = frame
        self.client = bytearray()
        self.guest = bytearray()
        self.local_acks = 0
        self.features_pending = False
        self.packets = {"p": 0, "P": 0, "g": 0, "G": 0}

    @staticmethod
    def take(buffer):
        if buffer[0] != ord("$"):
            byte = bytes(buffer[:1])
            del buffer[:1]
            assert byte in (b"+", b"-"), "unexpected RSP prefix"
            return byte, None
        end = buffer.find(b"#")
        if end < 0 or len(buffer) < end + 3:
            assert len(buffer) <= 1 << 20, "oversized proxy packet"
            return None
        wire = bytes(buffer[:end + 3])
        del buffer[:end + 3]
        raw = wire[1:-3]
        assert sum(raw) % 256 == int(wire[-2:], 16), "invalid proxy checksum"
        payload = bytearray()
        i = 0
        while i < len(raw):
            if raw[i] == ord("}"):
                i += 1
                assert i < len(raw), "invalid proxy escape"
                payload.append(raw[i] ^ 32)
            else:
                payload.append(raw[i])
            i += 1
        return wire, bytes(payload)

    def feed_client(self, data):
        self.client.extend(data)
        while self.client:
            item = self.take(self.client)
            if item is None:
                return
            wire, payload = item
            if payload is None:
                if self.local_acks:
                    assert wire == b"+", "local unsupported reply was rejected"
                    self.local_acks -= 1
                else:
                    self.to_guest(wire)
                continue
            if payload[:1] in (b"p", b"P"):
                self.packets[payload[:1].decode()] += 1
                self.local_acks += 1
                self.to_client(b"+" + self.frame(b""))
                continue
            if payload == b"g" or payload.startswith(b"G"):
                self.packets[payload[:1].decode()] += 1
            if payload.startswith(b"qSupported"):
                self.features_pending = True
            assert payload != b"QStartNoAckMode", "proxy intentionally retains acknowledged mode"
            self.to_guest(wire)

    def feed_guest(self, data):
        self.guest.extend(data)
        while self.guest:
            item = self.take(self.guest)
            if item is None:
                return
            wire, payload = item
            if payload is not None and self.features_pending:
                # Both sides stay in acknowledged mode, so local unsupported
                # packets cannot accidentally desynchronize the real stub.
                self.features_pending = False
                payload = b";".join(p for p in payload.split(b";") if p != b"QStartNoAckMode+")
                wire = self.frame(payload)
            self.to_client(wire)
