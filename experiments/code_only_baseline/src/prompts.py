"""One fixed prompt; its only dynamic argument is a source-code string."""
from .io_utils import EXPERIMENT_ROOT, fingerprint


class Prompt:
    version = "code_only"
    protocol = "code_only_baseline"

    def __init__(self):
        self.system = (EXPERIMENT_ROOT / "prompts/system.txt").read_text(encoding="utf-8").rstrip("\n")
        self.user = (EXPERIMENT_ROOT / "prompts/user.txt").read_text(encoding="utf-8").rstrip("\n")
        if self.user.count("{code}") != 1:
            raise ValueError("the fixed user prompt must contain exactly one code placeholder")
        self.sha256 = fingerprint([self.version, self.system, self.user])

    def messages(self, code: str):
        if not isinstance(code, str):
            raise TypeError("only a source string can be passed to prompt construction")
        return [{"role": "system", "content": self.system},
                {"role": "user", "content": self.user.replace("{code}", code)}]
