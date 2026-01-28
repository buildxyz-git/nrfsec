import logging
import re
import telnetlib


logger = logging.getLogger(__name__)


class OpenOcdError(Exception):
    pass


class OpenOcdConnectionError(OpenOcdError):
    pass


class OpenOcdCommandError(OpenOcdError):
    pass


class OpenOcdClient:
    def __init__(self, host="127.0.0.1", port=4444, timeout=2.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._tn = None

    def connect(self):
        try:
            self._tn = telnetlib.Telnet(self.host, self.port, self.timeout)
        except OSError as exc:
            raise OpenOcdConnectionError(str(exc)) from exc
        # drain banner and prompt
        self._read_until_prompt()

    def close(self):
        if self._tn is not None:
            self._tn.close()
            self._tn = None

    def _read_until_prompt(self, timeout=None):
        if self._tn is None:
            return b""
        timeout = self.timeout if timeout is None else timeout
        data = self._tn.read_until(b"> ", timeout)
        if not data.endswith(b"> "):
            data += self._tn.read_until(b">", timeout)
        return data

    def command(self, cmd, timeout=None):
        if self._tn is None:
            self.connect()
        self._tn.write(cmd.encode("ascii") + b"\n")
        data = self._read_until_prompt(timeout)
        text = data.decode("utf-8", errors="ignore")
        lines = [line.rstrip() for line in text.splitlines()]
        cleaned = []
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped == cmd:
                continue
            if stripped == ">":
                continue
            cleaned.append(line)
        output = "\n".join(cleaned).strip()
        if re.search(r"\b(Error|error):", output):
            raise OpenOcdCommandError(output)
        return output


def _first_hex(text):
    match = re.search(r"0x([0-9a-fA-F]+)", text)
    if not match:
        return None
    return int(match.group(1), 16)


class OpenOcdTarget:
    def __init__(self, client):
        self.client = client

    def set_adapter_speed(self, freq_hz):
        if not freq_hz:
            return
        khz = int(freq_hz / 1000)
        if khz <= 0:
            return
        try:
            self.client.command("adapter speed {}".format(khz))
        except OpenOcdCommandError:
            logger.debug("OpenOCD adapter speed command rejected")

    def get_version(self):
        out = self.client.command("version")
        return out.splitlines()[0] if out else "openocd"

    def get_target_voltage(self):
        try:
            out = self.client.command("adapter voltage")
        except OpenOcdCommandError:
            return None
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)", out)
        if not match:
            return None
        try:
            return float(match.group(1))
        except ValueError:
            return None

    def get_idcode(self):
        try:
            out = self.client.command("dap info")
        except OpenOcdCommandError:
            return 0
        match = re.search(r"idcode:\s*0x([0-9a-fA-F]+)", out)
        if not match:
            match = re.search(r"0x([0-9a-fA-F]{8})", out)
        if not match:
            return 0
        return int(match.group(1), 16)

    def get_mem32(self, address):
        out = self.client.command("mdw 0x{:08X} 1".format(address))
        values = re.findall(r"0x([0-9a-fA-F]{8})", out)
        if len(values) >= 2:
            return int(values[-1], 16)
        # OpenOCD sometimes prints "0xADDR: VALUE" without 0x on VALUE
        for line in out.splitlines():
            if ":" not in line:
                continue
            tail = line.split(":", 1)[1]
            match = re.search(r"\b([0-9a-fA-F]{1,8})\b", tail)
            if match:
                return int(match.group(1), 16)
        raise OpenOcdCommandError("mdw output not understood: {}".format(out))

    def set_mem32(self, address, value):
        self.client.command("mww 0x{:08X} 0x{:08X}".format(address, value))

    def read_mem16(self, address, length):
        if length <= 0:
            return b""
        words = int((length + 3) / 4)
        data = bytearray()
        for idx in range(words):
            value = self.get_mem32(address + (idx * 4))
            data.extend(value.to_bytes(4, byteorder="little"))
        return bytes(data[:length])


class OpenOcdCortexM:
    def __init__(self, client):
        self.client = client

    def halt(self):
        self.client.command("halt")

    def reset_halt(self):
        self.client.command("reset halt")

    def reset(self):
        self.client.command("reset")

    def run(self):
        self.client.command("resume")

    def step(self):
        self.client.command("step")

    def nodebug(self):
        self.client.command("resume")

    def is_halted(self):
        out = self.client.command("targets")
        return "halted" in out.lower()

    def get_reg(self, name):
        reg_name = _openocd_reg_name(name)
        out = self.client.command("reg {}".format(reg_name))
        value = _first_hex(out)
        if value is None:
            raise OpenOcdCommandError("reg output not understood: {}".format(out))
        return value

    def set_reg(self, name, value):
        reg_name = _openocd_reg_name(name)
        self.client.command("reg {} 0x{:08X}".format(reg_name, value))

    def get_reg_all(self):
        out = self.client.command("reg")
        regs = {}
        for line in out.splitlines():
            match = re.search(r"(?:\(\d+\)\s*)?([a-zA-Z0-9_]+)\s*\(/?\d*\)?:\s*0x([0-9a-fA-F]+)", line)
            if not match:
                continue
            name = match.group(1)
            value = int(match.group(2), 16)
            mapped = _normalize_reg_name(name)
            regs[mapped] = value
        return regs


def _normalize_reg_name(name):
    lower = name.lower()
    if lower == "xpsr":
        return "PSR"
    if lower in {"sp", "r13"}:
        return "SP"
    if lower in {"lr", "r14"}:
        return "LR"
    if lower in {"pc", "r15"}:
        return "PC"
    if lower == "msp":
        return "MSP"
    if lower == "psp":
        return "PSP"
    if lower.startswith("r") and lower[1:].isdigit():
        return "R{}".format(int(lower[1:]))
    return name.upper()


def _openocd_reg_name(name):
    upper = name.upper()
    if upper == "PSR":
        return "xpsr"
    if upper == "SP":
        return "sp"
    if upper == "LR":
        return "lr"
    if upper == "PC":
        return "pc"
    if upper == "MSP":
        return "msp"
    if upper == "PSP":
        return "psp"
    if upper.startswith("R") and upper[1:].isdigit():
        return "r{}".format(int(upper[1:]))
    return name.lower()
