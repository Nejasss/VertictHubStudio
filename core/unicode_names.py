"""
unicode_names.py - generates random Python identifiers made of CJK
(Han) characters, as an alternative to the plain-ASCII
`_abc123`-style names identifier_rename.py and string_enc.py
generate by default.

WHY THIS EXISTS
Every name this tool randomizes (local variables, function/class
names, the string-decrypt helper function, the gate-token-mixing
helpers, etc.) is, by default, an underscore followed by lowercase
ASCII letters/digits. That's already opaque in the sense that it
carries no semantic meaning - but it's still visually and
statistically indistinguishable from "ordinary obfuscated Python",
which is itself a known fingerprint: a `strings`/`dis` dump full of
`_qwqzxklm`-shaped names is exactly what a reverse engineer expects
to see from ANY off-the-shelf Python obfuscator, and tooling built to
recognize that shape (regexes, entropy heuristics keyed on the
ASCII alphabet) works just as well here as anywhere else. Using CJK
identifiers instead doesn't make analysis harder in a deep
cryptographic sense (a human or decompiler can still read a CJK
identifier as "just a name" the same way they'd read `_qwqzxklm`),
but it does:
  - break naive ASCII-only obfuscation-signature heuristics
  - look distinctly different from generic Python-obfuscator output
  - is completely legal Python: PEP 3131 allows any Unicode
    "identifier" category character (which the Han block qualifies
    as - see _CJK_CODEPOINT_RANGES below) anywhere in a name, so
    these run through CPython's own tokenizer/compiler with zero
    special-casing needed anywhere else in the pipeline.

CYTHON CAVEAT (read before enabling cjk_identifiers for a Cython
build): Cython's tokenizer also accepts PEP 3131 Unicode identifiers
in .pyx source, so this generally works for the Cython pipeline too
- but Cython additionally bakes CERTAIN identifiers (module-level
function/method names specifically - see identifier_rename.py's own
docstring on this) into the compiled extension as C string literals
for traceback/introspection support, and older Cython/C-compiler-
toolchain combinations on some platforms have had encoding bugs
around non-ASCII names in that specific code path. This has NOT
been exercised against this project's own Cython build pipeline yet
(no Cython available in the dev/test sandbox this change was made
in - see tests/run_regression.py's cjk test for exactly what WAS
verified: that generated source parses, compiles, and round-trips
correctly under plain CPython). Treat cjk_identifiers + Cython
together as unverified until tried against a real Cython toolchain;
cjk_identifiers with the marshal/embed pipelines (which only ever
need CPython's own compiler, never Cython's) has no such caveat.

FAKE CJK COMMENTS
generate_fake_comment() produces a short, syntactically-plausible-
looking but semantically meaningless CJK comment line (e.g. "# 正在
初始化系统核心模块"-style). These are pure decoration - inserted by
junk.py (when cjk_identifiers is on) alongside the junk code it
already generates, purely to make a source dump look like it
originated from a CJK-speaking codebase rather than to hide anything
specific. They carry no functional meaning and are never referenced
by real code, same as every other junk artifact this tool produces.
"""
import random

# A curated set of common, simple-stroke CJK Unified Ideographs
# (U+4E00-U+9FFF block). Deliberately NOT the full block (which
# includes many rare/complex characters) - this subset is chosen for
# characters that render cleanly in virtually any font/terminal a
# reverse engineer might view the dump in, avoiding boxes/tofu for
# unsupported codepoints which would itself be a visual tell.
_CJK_CHARS = (
    "一二三四五六七八九十"
    "人入八几刀力又口土士夕大女子小山川工己已巳"
    "天夫太少日月木水火父王井开夭无云支"
    "东丝丞丢両严丧个丫丬丰临丶丷"
    "东丽举乃久乇么义乌乐乔习乡书买"
    "乱乳乾了予争事二亏云亘亚"
    "些亦亥亨享京亮亲人亿仁仅"
    "今介仍从仑仓仔仕他仗付仙"
    "代令以仪们仰仲件价任份仿"
    "企伊伍伎伏伐休众优伙会伞"
    "伟传伤伦伪伯估伴伸似伽但"
    "位低住佐佑体何余佛作你佣"
    "佩佳使侃侄供依侠侣侦侧侨"
    "侬侯侵便促俄俊俏俐俗俘俚"
    "保信俭修俯俱倍倒倔倘候倚"
    "倦借倩倪值倾假偏做停健偶"
    "偷偿傍傅傲储催傻像僚僧僵"
    "儿元兄充兆先光克免兑兔党"
    "兜入全两八公六兰共关兴其"
    "兹再冒冠冬冰冲决况冷冻净"
    "凄准凉凌减凑几凡凤凭凯凰"
    "出击函刀刁分切刊刑划列刘"
    "则刚创初删判利别刨刮到制"
    "刷券刹刺刻剂剃削前剑剔剖"
    "剥剧剩剪副割创力劣劲办功"
    "加务劫动助努劳势勇勉勋勒"
    "勘募勤勾勿匀包匆化北匙匝"
    "匠匡匣匪匹区医华协单卖南"
    "博卜占卡卢卤卫卯印危即却"
    "卵卷厂厄厅历厉压厌厕厘厚"
    "原厢厥厦厨去参又叉及友双"
    "反发叔叙叛变叠口古句另叫"
)


def _rand_cjk_char() -> str:
    return random.choice(_CJK_CHARS)


def rand_cjk_identifier(n: int = 6) -> str:
    """
    Returns a random valid Python identifier made of CJK characters,
    e.g. "变量水火山" for n=5. Prefixed with a single underscore, same
    convention every ASCII generator in this project already uses,
    so call sites that string-concat or pattern-match on "starts with
    _" keep working unmodified regardless of which naming mode is
    active.

    n is a character count, not a byte count - CJK characters are all
    identifier-legal under PEP 3131 individually, so no digit/prefix
    juggling like the ASCII generators need (those avoid a leading
    digit because e.g. "123abc" isn't a legal identifier; every
    character in _CJK_CHARS is legal in ANY identifier position,
    including first, so that whole class of constraint doesn't apply
    here).
    """
    n = max(n, 1)
    return "_" + "".join(_rand_cjk_char() for _ in range(n))


def rand_cjk_identifier_unique(existing: set, n: int = 6) -> str:
    """Same as rand_cjk_identifier, but guarantees the result isn't
    already in `existing` (mirrors identifier_rename.py's _rand_name
    collision-avoidance loop for its ASCII names)."""
    while True:
        cand = rand_cjk_identifier(n)
        if cand not in existing:
            return cand


# A small set of short, generic-sounding (but semantically empty)
# CJK phrase fragments, combined at random into a full fake comment
# line by generate_fake_comment(). Kept deliberately vague/generic
# ("initializing", "system", "module", "checking") rather than
# specific claims, so nothing here is a false statement about what
# the surrounding code actually does - it's decorative noise, not a
# misleading label.
_FAKE_COMMENT_FRAGMENTS = (
    "正在初始化", "系统核心", "模块加载中", "检查配置",
    "数据同步", "缓存刷新", "内部状态", "运行时环境",
    "安全校验", "资源释放", "临时变量", "调度队列",
    "网络连接", "本地存储", "版本信息", "日志记录",
)


def generate_fake_comment() -> str:
    """Returns one fake CJK comment line (WITHOUT a leading '#' - the
    caller adds that, consistent with how junk.py already assembles
    its other comment/code fragments), e.g. "# 正在初始化 系统核心".
    Purely decorative junk - see module docstring."""
    parts = random.sample(_FAKE_COMMENT_FRAGMENTS, k=random.randint(1, 2))
    return "# " + " ".join(parts)


def make_identifier_generator(use_cjk: bool, ascii_fallback):
    """
    Returns a zero/one-arg-compatible callable name generator: if
    use_cjk is True, returns rand_cjk_identifier_unique-based
    generator; otherwise returns ascii_fallback unchanged. Centralizes
    the "which naming mode is this build using" branch in one place
    so identifier_rename.py/string_enc.py's call sites don't each
    need their own if/else - they just call whatever this returns the
    same way they'd call their own original ASCII-only helper.

    ascii_fallback must have the SAME calling convention as the
    function it's replacing at each call site: identifier_rename.py's
    _rand_name(existing, n) takes a collision set and an int length;
    string_enc.py's _rand_py_identifier(n) takes only a length. This
    helper is generic over both by simply not caring about arg count
    itself - it's the CALLER's job to pass the right ascii_fallback
    and to call the returned generator with the same arguments it
    would have called ascii_fallback with.
    """
    if not use_cjk:
        return ascii_fallback

    def _gen(*args, **kwargs):
        # Dispatch on arity/shape to match either convention:
        # _rand_name(existing_set, n) or _rand_py_identifier(n).
        if args and isinstance(args[0], set):
            existing = args[0]
            n = args[1] if len(args) > 1 else kwargs.get("n", 6)
            return rand_cjk_identifier_unique(existing, n)
        n = args[0] if args else kwargs.get("n", 6)
        return rand_cjk_identifier(n)

    return _gen
