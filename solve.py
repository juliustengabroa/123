"""
Solver for the macro CTF in main.rs.
It reimplements the n!/m! tt-muncher logic so you can test candidate flags
without waiting minutes for rustc to expand the macros.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple, Optional, Union

Token = Union[str, List["Token"]]


# --------------------- parsing helpers ---------------------
def tokenize_brackets(expr: str) -> List[Token]:
    """
    Parse a bracketed token stream like "[S K] A []" into nested Python lists.
    Tokens are split on whitespace and [ ].
    """
    tokens = re.findall(r"\[|\]|[^\s\[\]]+", expr)
    stack: List[List[Token]] = [[]]
    for tok in tokens:
        if tok == "[":
            stack.append([])
        elif tok == "]":
            if len(stack) == 1:
                raise ValueError("unmatched ]")
            finished = stack.pop()
            stack[-1].append(finished)
        else:
            stack[-1].append(tok)
    if len(stack) != 1:
        raise ValueError("unclosed [")
    return stack[0]


def deep_clone(t: Token) -> Token:
    if isinstance(t, list):
        return [deep_clone(x) for x in t]
    return t


# --------------------- data extraction ---------------------
ROOT = Path(__file__).resolve().parent
MAIN_RS = ROOT / "main.rs"

# Extract the big constant list inside the n! base case: m!($a* E K [-] <HERE> [] U)
def extract_big_list() -> List[Token]:
    src = MAIN_RS.read_text()

    def find_call(start: int) -> Optional[Tuple[int, int, str]]:
        idx = src.find("m!(", start)
        if idx == -1:
            return None
        depth = 0
        i = idx
        while i < len(src):
            if src[i] == "(":
                depth += 1
            elif src[i] == ")":
                depth -= 1
                if depth == 0:
                    return idx, i, src[idx + 3 : i]
            i += 1
        return None

    pos = 0
    payload = None
    while True:
        found = find_call(pos)
        if not found:
            break
        idx, end, body = found
        pos = end + 1
        if "E K [-]" in body and "[] U" in body:
            payload = body
            break
    if payload is None:
        raise RuntimeError("could not locate base m! payload in main.rs")

    m = re.search(r"E K \[-\]\s*(\[[^\)]*\])\s*\[\]\s*U", payload, re.S)
    if not m:
        raise RuntimeError("could not capture big list from payload")
    raw_list = m.group(1)
    parsed = tokenize_brackets(raw_list)
    if len(parsed) != 1 or not isinstance(parsed[0], list):
        raise RuntimeError("unexpected parse of payload")
    return parsed[0]


BIG_LIST = extract_big_list()

# Params passed to n! from input! macro (26 entries)
PARAMS: List[List[str]] = [
    ["I", "I", "K", "I"],
    ["S", "K", "S", "I"],
    ["I", "K", "S", "I"],
    ["I", "S", "I"],
    ["I", "K", "I", "I"],
    ["I", "S", "S", "S", "I"],
    ["I", "S", "K", "K", "I"],
    ["S", "S", "K", "I"],
    ["I", "K", "S", "K", "I"],
    ["S", "S", "I", "S", "I"],
    ["S", "I", "S", "S", "I"],
    ["S", "I", "I"],
    ["I", "S", "I", "S", "I"],
    ["I", "I", "I", "S", "I"],
    ["I", "I", "I"],
    ["I", "S", "S", "I", "I"],
    ["S", "I"],
    ["S", "S", "S", "S", "I"],
    ["I", "I", "S", "I", "I"],
    ["S", "S", "I"],
    ["S", "I", "K", "K", "I"],
    ["S", "K", "K", "S", "I"],
    ["S", "I", "S", "I", "I"],
    ["S", "K", "S", "K", "I"],
    ["S", "I", "K", "I"],
    ["S", "K", "I", "K", "I"],
]

# Per-character combinator chunks from n! rules
CHAR_MAP = {
    "A": ["S", "S", "S", "I", "I"],
    "B": ["I", "I", "I", "K", "I"],
    "C": ["I", "S", "K", "S", "I"],
    "D": ["K", "I", "K", "I"],
    "E": ["K", "K", "I", "I"],
    "F": ["S", "I", "K", "S", "I"],
    "G": ["I", "K", "I", "I"],
    "H": ["S", "S", "S", "S", "I"],
    "I": ["I", "I", "I", "I"],
    "J": ["S", "K", "S", "I", "I"],
    "K": ["I", "K", "I", "K", "I"],
    "L": ["S", "I", "I"],
    "M": ["K", "S", "S", "K", "I"],
    "N": ["I", "K", "K", "I"],
    "O": ["K", "I", "K", "K", "I"],
    "P": ["S", "I", "I", "I"],
    "Q": ["S", "S", "K", "I"],
    "R": ["I", "K", "I", "S", "I"],
    "S": ["S", "K", "I", "S", "I"],
    "T": ["I", "K", "S", "K", "I"],
    "U": ["I", "K", "K", "S", "I"],
    "V": ["S", "S", "I", "S", "I"],
    "W": ["I", "I", "I"],
    "X": ["K", "S", "S", "I"],
    "Y": ["I", "S", "K", "I"],
    "Z": ["S", "I", "I", "K", "I"],
    "a": ["K", "I", "S", "I"],
    "b": ["K", "I", "S", "S", "I"],
    "c": ["S", "K", "K", "K", "I"],
    "d": ["K", "K", "I", "S", "I"],
    "e": ["I", "K", "S", "I"],
    "f": ["I", "I", "K", "I"],
    "g": ["S", "I", "K", "K", "I"],
    "h": ["S", "K", "S", "I"],
    "i": ["I", "I", "K", "K", "I"],
    "j": ["I", "I", "S", "S", "I"],
    "k": ["I", "S", "S", "K", "I"],
    "l": ["S", "S", "K", "K", "I"],
    "m": ["S", "S", "S", "K", "I"],
    "n": ["S", "S", "S", "I"],
    "o": ["S", "K", "K", "S", "I"],
    "p": ["K", "I", "I", "S", "I"],
    "q": ["K", "K", "K", "S", "I"],
    "r": ["K", "S", "K", "I"],
    "s": ["I", "S", "S", "I"],
    "t": ["S", "K", "I", "K", "I"],
    "u": ["K", "S", "K", "K", "I"],
    "v": ["I", "S", "S", "I", "I"],
    "w": ["K", "K", "S", "I", "I"],
    "x": ["I", "K", "S", "S", "I"],
    "y": ["K", "S", "I", "S", "I"],
    "z": ["S", "I", "S", "K", "I"],
    "_": ["I", "S", "I", "S", "I"],
}


# --------------------- encoder (n!) ---------------------
def encode_input(user_input: str) -> List[Token]:
    params = [deep_clone(p) for p in PARAMS]
    acc: List[Token] = ["A", ["I"]]  # from n!([A [I]] ...)

    for ch in user_input:
        if ch not in CHAR_MAP:
            raise ValueError(f"unsupported char {ch!r}")
        if not params:
            raise ValueError("ran out of params (input too long)")
        c_param = params.pop(0)
        acc.extend(
            [
                "N",
                "D",
                deep_clone(c_param),
                deep_clone(CHAR_MAP[ch]),
                "K",
                "E",
                "B",
                [],
            ]
        )

    # Build final m! payload: $a* E K [-] [BIG_LIST] [] U
    return acc + ["E", "K", ["-"], deep_clone(BIG_LIST), [], "U"]


# --------------------- matcher utilities ---------------------
def split_head(lst: Token) -> Optional[Tuple[str, List[Token]]]:
    if not isinstance(lst, list) or not lst:
        return None
    head, tail = lst[0], lst[1:]
    if not isinstance(head, str):
        return None
    return head, tail


def expect_prefix(lst: Token, prefix: List[str]) -> Optional[List[Token]]:
    if not isinstance(lst, list):
        return None
    if len(lst) < len(prefix):
        return None
    if any(not isinstance(lst[i], str) or lst[i] != prefix[i] for i in range(len(prefix))):
        return None
    return lst[len(prefix) :]


def capture_dashdash(lst: Token, leading: int = 0) -> Optional[List[Token]]:
    """
    Match lists of the form [-]* (len=leading) followed by zero or more (tok '--') groups.
    Returns captured tok values (without the separators) if it matches, else None.
    """
    if not isinstance(lst, list):
        return None
    if leading and (len(lst) < leading or any(x != "-" for x in lst[:leading])):
        return None
    idx = leading
    captured: List[Token] = []
    while idx < len(lst):
        if idx + 2 >= len(lst) or lst[idx + 1] != "-" or lst[idx + 2] != "-":
            return None
        captured.append(lst[idx])
        idx += 3
    return captured


# --------------------- m! rewrite rules ---------------------
def rule1(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "S" and t[1] == ["-"] and t[2] == [] and t[3] == []:
        a, b = t[4], t[5]
        return [deep_clone(b), deep_clone(a)] + t[6:]
    return None


def rule2(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "K" and t[1] == ["-"] and t[2] == [] and t[3] == []:
        a, b = t[4], t[5]
        return [deep_clone(b), deep_clone(a)] + t[6:]
    return None


def rule3(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "I" and isinstance(t[1], list) and t[1] and t[1][0] == "S":
        new_list = deep_clone(t[1][1:])
        return ["I", new_list, t[2], t[3], t[4], t[5]] + t[6:]
    return None


def rule4(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 5 and t[0] == "B" and t[2] == []:
        a, b, c = t[1], t[3], t[4]
        return [deep_clone(c), deep_clone(a)] + t[5:]
    return None


def rule5(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "I" and isinstance(t[1], list) and t[1] and t[1][0] == "K":
        new_list = deep_clone(t[1][1:]) + ["-"]
        return ["I", new_list, t[2], t[3], t[4], t[5]] + t[6:]
    return None


def rule6(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 5 and t[0] == "D" and t[2] == ["I"] and t[3] == "K":
        a, b = t[1], t[4]
        return [deep_clone(b), deep_clone(a)] + t[5:]
    return None


def rule7(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "I" and isinstance(t[1], list) and t[1] and t[1][0] == "I":
        new_list = deep_clone(t[1][1:]) + ["-", "-"]
        return ["I", new_list, t[2], t[3], t[4], t[5]] + t[6:]
    return None


def rule8(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 3 and t[0] == "A":
        a, b = t[1], t[2]
        return [deep_clone(b), deep_clone(a)] + t[3:]
    return None


def rule9(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "S" and isinstance(t[1], list) and isinstance(t[2], list) and isinstance(t[3], list):
        head2 = split_head(t[2])
        head3 = split_head(t[3])
        if head2 and head3:
            b, rest2 = head2
            d, rest3 = head3
            new1 = [b, d] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest2), deep_clone(rest3), t[4], "S"] + t[5:]
    return None


def rule10(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "K" and isinstance(t[1], list) and isinstance(t[2], list) and isinstance(t[3], list):
        head2 = split_head(t[2])
        head3 = split_head(t[3])
        if head2 and head3 and head3[0] == "S":
            b, rest2 = head2
            _, rest3 = head3
            new1 = [b, "-", "-"] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest2), deep_clone(rest3), t[4], "K"] + t[5:]
    return None


def rule11(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "I":
        captured = capture_dashdash(t[1], leading=0)
        if captured is not None and isinstance(t[4], list):
            new_d = deep_clone(t[4]) + ["K"]
            return [t[5], deep_clone(captured), t[2], t[3], new_d] + t[6:]
    return None


def rule12(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "B" and isinstance(t[2], list) and t[2] and t[2][0] == "K" and isinstance(t[3], list):
        b_list = deep_clone(t[2][1:])
        new3 = ["K"] + deep_clone(t[3])
        return ["B", deep_clone(t[1]), b_list, new3] + t[4:]
    return None


def rule13(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "I" and isinstance(t[1], list) and t[1] and t[1][0] == "-":
        captured = capture_dashdash(t[1], leading=1)
        if captured is not None and isinstance(t[4], list):
            new_d = deep_clone(t[4]) + ["I"]
            return [t[5], deep_clone(captured), t[2], t[3], new_d] + t[6:]
    return None


def rule14(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and t[2] == ["I"] and t[3] == "S":
        return [deep_clone(t[1]), ["I"]] + t[4:]
    return None


def rule15(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "I" and isinstance(t[1], list) and len(t[1]) >= 2 and t[1][0] == "-" and t[1][1] == "-":
        captured = capture_dashdash(t[1], leading=2)
        if captured is not None and isinstance(t[4], list):
            new_a = ["-"] + deep_clone(captured)
            new_d = deep_clone(t[4]) + ["S"]
            return [t[5], new_a, t[2], t[3], new_d] + t[6:]
    return None


def rule16(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "E":
        return [t[1], t[2], t[3]] + t[4:]
    return None


def rule17(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "K" and isinstance(t[1], list) and isinstance(t[2], list) and isinstance(t[3], list):
        head2 = split_head(t[2])
        head3 = split_head(t[3])
        if head2 and head3 and head3[0] == "K":
            b, rest2 = head2
            _, rest3 = head3
            new1 = [b, "-"] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest2), deep_clone(rest3), t[4], "K"] + t[5:]
    return None


def rule18(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "S" and isinstance(t[1], list) and isinstance(t[2], list) and isinstance(t[3], list) and t[3] == []:
        head2 = split_head(t[2])
        if head2:
            b, rest2 = head2
            new1 = [b, "-"] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest2), [], t[4], "S"] + t[5:]
    return None


def rule19(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "K" and isinstance(t[1], list) and isinstance(t[2], list) and isinstance(t[3], list):
        head2 = split_head(t[2])
        head3 = split_head(t[3])
        if head2 and head3 and head3[0] == "I":
            b, rest2 = head2
            _, rest3 = head3
            new1 = [b] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest2), deep_clone(rest3), t[4], "K"] + t[5:]
    return None


def rule20(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and isinstance(t[2], list) and t[2] and t[2][0] == "K" and t[3] == "K":
        b_list = deep_clone(t[2][1:])
        if not b_list:
            return None
        a = t[1]
        return ["B", [], deep_clone(a), deep_clone(a), "E", "B", [], deep_clone(a), "D", b_list, "K"] + t[4:]
    return None


def rule21(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and isinstance(t[2], list) and t[2] and t[2][0] == "K" and t[3] == "S":
        b_list = deep_clone(t[2][1:])
        if not b_list:
            return None
        a = t[1]
        return [
            "B",
            [],
            deep_clone(a),
            deep_clone(a),
            "E",
            "B",
            [],
            deep_clone(a),
            "D",
            b_list,
            "S",
            "E",
            "B",
            [],
            deep_clone(a),
            "E",
            "B",
            [],
            deep_clone(a),
        ] + t[4:]
    return None


def rule22(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "K" and isinstance(t[1], list) and isinstance(t[2], list) and t[3] == []:
        head2 = split_head(t[2])
        if head2:
            b, rest2 = head2
            new1 = [b, "-"] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest2), [], t[4], "K"] + t[5:]
    return None


def rule23(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "B" and isinstance(t[2], list) and t[2] and t[2][0] == "I" and isinstance(t[3], list):
        b_list = deep_clone(t[2][1:])
        c_list = deep_clone(t[3])
        return ["S", ["-"], deep_clone(t[1]), c_list, [], "B", b_list, ["K"] + c_list] + t[4:]
    return None


def rule24(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "S" and isinstance(t[1], list) and t[2] == [] and t[3] == []:
        new_list = deep_clone(t[1]) + ["-", "-"]
        return ["I", new_list, [], [], t[4], "S"] + t[5:]
    return None


def rule25(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and isinstance(t[2], list) and t[2] and t[2][0] == "I" and t[3] == "K":
        b_list = deep_clone(t[2][1:])
        if not b_list:
            return None
        a = t[1]
        return ["B", [], deep_clone(a), deep_clone(a), "E", "B", [], deep_clone(a), "D", b_list, "K", "E", "B", [], deep_clone(a)] + t[4:]
    return None


def rule26(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "K" and isinstance(t[1], list) and t[2] == [] and t[3] == []:
        new_list = deep_clone(t[1]) + ["-", "-"]
        return ["I", new_list, [], [], t[4], "K"] + t[5:]
    return None


def rule27(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and isinstance(t[2], list) and t[2] and t[2][0] == "I" and t[3] == "S":
        b_list = deep_clone(t[2][1:])
        if not b_list:
            return None
        a = t[1]
        return ["B", [], deep_clone(a), deep_clone(a), "E", "B", [], deep_clone(a), "D", b_list, "K"] + t[4:]
    return None


def rule28(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "B" and isinstance(t[2], list) and t[2] and t[2][0] == "S" and isinstance(t[3], list):
        b_list = deep_clone(t[2][1:])
        c_list = deep_clone(t[3])
        return ["K", ["-"], deep_clone(t[1]), c_list, [], "B", b_list, ["K"] + c_list] + t[4:]
    return None


def rule29(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and isinstance(t[2], list) and t[2] and t[2][0] == "S" and t[3] == "K":
        b_list = deep_clone(t[2][1:])
        if not b_list:
            return None
        a = t[1]
        return [
            "B",
            [],
            deep_clone(a),
            deep_clone(a),
            "E",
            "B",
            [],
            deep_clone(a),
            "D",
            b_list,
            "S",
            "E",
            "B",
            [],
            deep_clone(a),
            "E",
            "B",
            [],
            deep_clone(a),
        ] + t[4:]
    return None


def rule30(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "K" and t[2] == []:
        return ["K", deep_clone(t[1]), ["K"], t[3], t[4]] + t[5:]
    return None


def rule31(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 9 and t[0] == "N":
        a, b, c, d, e, f, g, h = t[1:9]
        return [deep_clone(b), deep_clone(c), deep_clone(d), deep_clone(e), deep_clone(f), deep_clone(g), deep_clone(h), deep_clone(a)] + t[9:]
    return None


def rule32(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 6 and t[0] == "S" and isinstance(t[1], list) and t[2] == [] and isinstance(t[3], list):
        head3 = split_head(t[3])
        if head3:
            b, rest3 = head3
            new1 = [b, "-"] + deep_clone(t[1])
            return ["I", new1, deep_clone(rest3), [], t[4], "S"] + t[5:]
    return None


def rule33(t: List[Token]) -> Optional[List[Token]]:
    if len(t) >= 4 and t[0] == "D" and isinstance(t[2], list) and t[2] and t[2][0] == "S" and t[3] == "S":
        b_list = deep_clone(t[2][1:])
        if not b_list:
            return None
        a = t[1]
        return ["B", [], deep_clone(a), deep_clone(a), "E", "B", [], deep_clone(a), "D", b_list, "S", "E", "B", [], deep_clone(a)] + t[4:]
    return None


RULES = [
    rule1,
    rule2,
    rule3,
    rule4,
    rule5,
    rule6,
    rule7,
    rule8,
    rule9,
    rule10,
    rule11,
    rule12,
    rule13,
    rule14,
    rule15,
    rule16,
    rule17,
    rule18,
    rule19,
    rule20,
    rule21,
    rule22,
    rule23,
    rule24,
    rule25,
    rule26,
    rule27,
    rule28,
    rule29,
    rule30,
    rule31,
    rule32,
    rule33,
]


# --------------------- reducer ---------------------
def reduce_tokens(tokens: List[Token], max_steps: int = 5_000_000) -> Tuple[List[Token], int]:
    steps = 0
    current = tokens
    while steps < max_steps:
        steps += 1
        for rule in RULES:
            nxt = rule(current)
            if nxt is not None:
                current = nxt
                break
        else:
            return current, steps
    raise RuntimeError(f"exceeded max steps ({max_steps})")


def is_all_k_list(tok: Token) -> bool:
    return isinstance(tok, list) and all(x == "K" for x in tok)


def check_candidate(candidate: str) -> None:
    tokens = encode_input(candidate)
    reduced, steps = reduce_tokens(tokens)
    ok = len(reduced) == 2 and reduced[0] == "U" and is_all_k_list(reduced[1])
    print(f"input={candidate!r} steps={steps} result={reduced}")
    print("Correct flag!" if ok else "That's not the flag!")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python solve.py <candidate_string>")
        sys.exit(1)
    check_candidate(sys.argv[1])
