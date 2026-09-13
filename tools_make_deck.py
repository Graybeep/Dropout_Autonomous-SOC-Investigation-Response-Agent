"""Generate the PS9 pitch deck.

Same nine-slide skeleton the brief specified, populated with this project's
actual content. Visual language matches the site: cream ground, warm brown text,
one orange accent, serif headings.
"""
from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR

INK = RGBColor(0x1C, 0x1C, 0x1E)
BODY = RGBColor(0x4A, 0x4A, 0x52)
MUTED = RGBColor(0x8A, 0x8A, 0x94)
ORNG = RGBColor(0xE2, 0x55, 0x1F)
CREAM = RGBColor(0xFF, 0xFA, 0xF0)
WARM = RGBColor(0xFF, 0xF3, 0xE4)
CARD = RGBColor(0xFF, 0xFF, 0xFF)
LINE = RGBColor(0xE2, 0xD8, 0xCC)
GREEN = RGBColor(0x0B, 0x6B, 0x44)
RED = RGBColor(0xA8, 0x2D, 0x16)
AMBER = RGBColor(0x8A, 0x5E, 0x00)
DARK = RGBColor(0x0D, 0x0D, 0x0D)

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
W, H = prs.slide_width, prs.slide_height
BLANK = prs.slide_layouts[6]


def slide(bg=CREAM):
    s = prs.slides.add_slide(BLANK)
    r = s.shapes.add_shape(1, 0, 0, W, H)
    r.fill.solid()
    r.fill.fore_color.rgb = bg
    r.line.fill.background()
    r.shadow.inherit = False
    return s


def box(s, x, y, w, h, text, size=16, color=BODY, bold=False,
        align=PP_ALIGN.LEFT, font="Segoe UI", space_after=6, line=1.25):
    tb = s.shapes.add_textbox(x, y, w, h)
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = 0
    tf.margin_top = tf.margin_bottom = 0
    for i, ln in enumerate(text.split("\n")):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = Pt(space_after)
        p.line_spacing = line
        run = p.add_run()
        run.text = ln
        run.font.size = Pt(size)
        run.font.color.rgb = color
        run.font.bold = bold
        run.font.name = font
    return tb


def card(s, x, y, w, h, fill=CARD, border=LINE, accent=None):
    r = s.shapes.add_shape(5, x, y, w, h)
    r.fill.solid()
    r.fill.fore_color.rgb = fill
    r.line.color.rgb = border
    r.line.width = Pt(1)
    r.shadow.inherit = False
    try:
        r.adjustments[0] = 0.04
    except Exception:
        pass
    if accent:
        b = s.shapes.add_shape(1, x, y, Inches(0.055), h)
        b.fill.solid()
        b.fill.fore_color.rgb = accent
        b.line.fill.background()
        b.shadow.inherit = False
    return r


def header(s, kicker, title, weight=None, dark=False):
    tc = RGBColor(0xE4, 0xE4, 0xE7) if dark else INK
    box(s, Inches(.85), Inches(.5), Inches(9.8), Inches(.3),
        kicker.upper(), size=12, color=ORNG, bold=True)
    box(s, Inches(.85), Inches(.85), Inches(9.8), Inches(.9),
        title, size=31, color=tc, bold=True, font="Georgia")
    if weight:
        t = s.shapes.add_shape(5, Inches(10.98), Inches(.52), Inches(1.47), Inches(.44))
        t.fill.solid()
        t.fill.fore_color.rgb = WARM
        t.line.color.rgb = ORNG
        t.shadow.inherit = False
        tf = t.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        r = p.add_run()
        r.text = weight
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = ORNG
        r.font.name = "Segoe UI"


def arrow(s, x, y, color=MUTED):
    box(s, x, y, Inches(.32), Inches(.3), ">", size=17, color=color,
        bold=True, align=PP_ALIGN.CENTER)


# --------------------------------------------------------------- 1. Title
s = slide()
bar = s.shapes.add_shape(1, 0, 0, W, Inches(.13))
bar.fill.solid(); bar.fill.fore_color.rgb = ORNG
bar.line.fill.background(); bar.shadow.inherit = False
box(s, Inches(.85), Inches(1.45), Inches(11.6), Inches(.35),
    "PROBLEM STATEMENT 9", size=14, color=ORNG, bold=True)
box(s, Inches(.85), Inches(1.9), Inches(11.6), Inches(1.6),
    "Autonomous SOC Investigation\n& Response Agent",
    size=46, color=INK, bold=True, font="Georgia", line=1.05)
box(s, Inches(.85), Inches(3.72), Inches(10.8), Inches(.9),
    "An alert says you were attacked. The agent decides whether it actually worked,\n"
    "by correlating asset, vulnerability, configuration and log evidence rather than\n"
    "trusting the alert's own severity label.", size=17, color=BODY)
card(s, Inches(.85), Inches(5.0), Inches(5.5), Inches(1.35), accent=ORNG)
box(s, Inches(1.18), Inches(5.2), Inches(4.9), Inches(.3), "TEAM",
    size=11, color=MUTED, bold=True)
box(s, Inches(1.18), Inches(5.53), Inches(4.9), Inches(.6),
    "[ your team name here ]", size=19, color=INK, bold=True)
card(s, Inches(6.6), Inches(5.0), Inches(5.85), Inches(1.35))
box(s, Inches(6.93), Inches(5.2), Inches(5.3), Inches(.3), "LIVE PROTOTYPE",
    size=11, color=MUTED, bold=True)
box(s, Inches(6.93), Inches(5.53), Inches(5.3), Inches(.6),
    "soc-agent-trace-viewer.vercel.app", size=15, color=ORNG,
    bold=True, font="Consolas")

# --------------------------------------------------------------- 2. Problem
s = slide()
header(s, "The problem", "Alarms are cheap. Answers are not.", "10%")
y = Inches(1.95)
rows = [
    ("An alert is only a pattern match",
     "A detection rule fires when traffic LOOKS like an attack. It cannot tell you whether anything was actually breached."),
    ("The severity label is an opinion",
     "A critical signature against a host patched two years ago is noise. A quiet one against an unpatched host that then shipped 2 MB outbound is a breach."),
    ("So a human checks, every single time",
     "An analyst pulls asset data, CVE ranges, host logs, configuration and packet metadata, joins them, and decides. Then does it again."),
]
for t, d in rows:
    card(s, Inches(.85), y, Inches(11.6), Inches(1.02))
    box(s, Inches(1.18), y + Inches(.15), Inches(6.0), Inches(.35), t,
        size=17, color=INK, bold=True)
    box(s, Inches(1.18), y + Inches(.55), Inches(10.9), Inches(.4), d,
        size=13, color=BODY)
    y += Inches(1.16)

card(s, Inches(.85), Inches(5.55), Inches(11.6), Inches(1.3), fill=WARM, accent=ORNG)
box(s, Inches(1.2), Inches(5.75), Inches(11.0), Inches(.32),
    "WHY THIS NEEDS AN AGENT AND NOT A SCRIPT", size=12, color=ORNG, bold=True)
box(s, Inches(1.2), Inches(6.1), Inches(11.0), Inches(.65),
    "The evidence that settles one alert is not the evidence that settles the next, and what the agent finds changes what it "
    "should look at next. A script fixes that order in advance. Here the agent chooses each call, states why before making it, "
    "and re-plans when new evidence arrives mid-investigation.", size=13, color=BODY)

# --------------------------------------------------------------- 3. Architecture
s = slide()
header(s, "Agentic architecture", "The agent picks its own path through the loop", "25%")
stages = [("INGEST", "an alert\nopens a case"),
          ("HYPOTHESIZE", "what confirms?\nwhat falsifies?"),
          ("GATHER", "pick a tool,\nsay why, assess"),
          ("DETERMINE", "declare evidence,\nscore it"),
          ("ACT", "block, contain\nor do nothing"),
          ("VERIFY", "re-read state\nfrom disk")]
x = Inches(.85)
w = Inches(1.74)
for i, (t, d) in enumerate(stages):
    acc = ORNG if t in ("HYPOTHESIZE", "VERIFY") else None
    card(s, x, Inches(1.95), w, Inches(1.45), accent=acc)
    box(s, x + Inches(.14), Inches(2.12), w - Inches(.28), Inches(.3), t,
        size=11, color=ORNG if acc else INK, bold=True, align=PP_ALIGN.CENTER)
    box(s, x + Inches(.14), Inches(2.48), w - Inches(.28), Inches(.75), d,
        size=10.5, color=BODY, align=PP_ALIGN.CENTER)
    if i < 5:
        arrow(s, x + w + Inches(.01), Inches(2.5))
    x += w + Inches(.22)

box(s, Inches(.85), Inches(3.62), Inches(11.6), Inches(.35),
    "reconsider() re-enters at HYPOTHESIZE, never at the verdict",
    size=16, color=ORNG, bold=True)
box(s, Inches(.85), Inches(4.0), Inches(11.6), Inches(.6),
    "New evidence, a tool failure and a human override all route through one function. It re-opens the case at the hypothesis "
    "stage so the agent gathers NEW evidence, instead of silently re-scoring what it already had.",
    size=13, color=BODY)

card(s, Inches(.85), Inches(4.85), Inches(5.65), Inches(1.95))
box(s, Inches(1.18), Inches(5.05), Inches(5.1), Inches(.3), "FRAMEWORK",
    size=11, color=MUTED, bold=True)
box(s, Inches(1.18), Inches(5.4), Inches(5.1), Inches(1.3),
    "No LangChain, no AutoGen. A hand-written tool-use loop on the model's "
    "native tool calling, so the reasoning trace is ours and every decision "
    "point is inspectable rather than hidden inside a framework.",
    size=12.5, color=BODY)
card(s, Inches(6.8), Inches(4.85), Inches(5.65), Inches(1.95))
box(s, Inches(7.13), Inches(5.05), Inches(5.1), Inches(.3), "THE MODEL CHOOSES",
    size=11, color=MUTED, bold=True)
box(s, Inches(7.13), Inches(5.4), Inches(5.1), Inches(1.3),
    "Which tool, in what order, and when it has enough to stop. Nothing about "
    "the sequence is scripted: measured across runs, the outcome is identical "
    "while the trajectory genuinely varies.",
    size=12.5, color=BODY)

# --------------------------------------------------------------- 4. Sandbox
s = slide()
header(s, "The sandbox", "Eleven tools, and a boundary it cannot cross", "15%")
cols = [
    ("CAN READ", GREEN, [
        "get_alert", "get_asset_info", "get_vulnerabilities",
        "get_configuration", "get_server_logs", "get_packet_metadata",
        "get_related_alerts", "check_firewall_state"],
     "Flat JSON fixtures a judge can open and read."),
    ("CAN ACT", RED, ["block_ip", "unblock_ip"],
     "Both mutate firewall_state.json. check_firewall_state reads that same "
     "file back from disk, which is what makes verification real rather than "
     "decorative."),
    ("CANNOT REACH", MUTED, [
        "real hosts", "credentials", "live network traffic",
        "any outbound call", "the pristine seed fixtures"],
     "Every hostname, IP, account and log line is synthetic."),
]
x = Inches(.85)
cw = Inches(3.72)
for title, col, items, note in cols:
    card(s, x, Inches(1.95), cw, Inches(4.35),
         fill=CARD if title != "CANNOT REACH" else RGBColor(0xFB, 0xF1, 0xEC))
    box(s, x + Inches(.28), Inches(2.15), cw - Inches(.56), Inches(.3),
        title, size=12, color=col, bold=True)
    yy = Inches(2.6)
    for it in items:
        box(s, x + Inches(.28), yy, cw - Inches(.56), Inches(.28), it,
            size=12.5, color=INK,
            font="Consolas" if title != "CANNOT REACH" else "Segoe UI")
        yy += Inches(.32)
    box(s, x + Inches(.28), Inches(5.35), cw - Inches(.56), Inches(.85),
        note, size=11.5, color=MUTED)
    x += cw + Inches(.22)

box(s, Inches(.85), Inches(6.5), Inches(11.6), Inches(.55),
    "The eleventh is submit_assessment: not a read and not an action, but how the agent declares what it found. "
    "It is the one tool that can refuse.", size=13, color=BODY)

# --------------------------------------------------------------- 5. Self-correction
s = slide()
header(s, "Self-correction", "A real refusal, and what the agent did next", "15%")
steps = [
    ("1  SUBMITS", "Declares the host patched, and cites a related alert as corroboration.", CARD, INK),
    ("2  REFUSED", "Two problems at once: it checked 2 of the host's 3 services, and the "
     "corroboration came from a lookup that returned no data.", RGBColor(0xFC, 0xED, 0xE9), RED),
    ("3  ITS OWN WORDS", "\"I need to fix two issues. Let me check openssh CVEs and remove the "
     "related_alert_corroborates factor since no_data is not a finding.\"", WARM, ORNG),
    ("4  RESOLVES BOTH", "Fetches the missing CVE data, and drops the claim it could not support. "
     "Resubmits. Accepted.", CARD, GREEN),
]
y = Inches(1.9)
for t, d, fill, col in steps:
    card(s, Inches(.85), y, Inches(11.6), Inches(.92), fill=fill,
         accent=col if col != INK else None)
    box(s, Inches(1.2), y + Inches(.14), Inches(2.4), Inches(.3), t,
        size=12.5, color=col, bold=True)
    box(s, Inches(3.5), y + Inches(.14), Inches(8.6), Inches(.65), d,
        size=13, color=BODY)
    y += Inches(1.02)

card(s, Inches(.85), Inches(6.0), Inches(11.6), Inches(.95), fill=WARM, accent=ORNG)
box(s, Inches(1.2), Inches(6.16), Inches(11.0), Inches(.7),
    "Measured across every run: the agent has NEVER resolved a refusal by rewording the same claim. It either fetches what it "
    "was missing, or it withdraws the claim. It does not negotiate.", size=13.5, color=INK, bold=True)

# --------------------------------------------------------------- 6. Technical
s = slide()
header(s, "Technical implementation", "Deterministic where it must be, free where it should be", "15%")
left = [
    ("MODEL AND PROVIDER",
     "Provider-agnostic by design. SOC_BASE_URL, SOC_MODEL and SOC_API_STYLE are "
     "environment-driven, and the client speaks both wire formats: x-api-key for the "
     "Anthropic surface, Bearer for OpenAI-compatible. Swapping provider is one line."),
    ("PROMPTING STRATEGY",
     "Not ReAct off the shelf. Reason-before-act is enforced structurally: every "
     "evidence tool takes a required `reason` parameter, so the trace cannot contain "
     "an unexplained call. After each result the agent must state whether it has enough."),
]
right = [
    ("SCORING IS NOT THE MODEL'S JOB",
     "The agent never emits a confidence number. It declares which evidence CLASSES it "
     "established and cites each one; a fixed table in Python turns those into a score. "
     "Same evidence, same score, every run."),
    ("THE TRACE IS THE SOURCE OF TRUTH",
     "Every call, reason, result, refusal and score lands in one structured trace. The "
     "viewer and the written case reports are both rendered from it, so neither can "
     "drift from what actually happened."),
]
for col, items in ((Inches(.85), left), (Inches(6.8), right)):
    y = Inches(1.95)
    for t, d in items:
        card(s, col, y, Inches(5.65), Inches(2.25))
        box(s, col + Inches(.33), y + Inches(.2), Inches(5.0), Inches(.3), t,
            size=11.5, color=ORNG, bold=True)
        box(s, col + Inches(.33), y + Inches(.58), Inches(5.0), Inches(1.5), d,
            size=12.5, color=BODY)
        y += Inches(2.4)

box(s, Inches(.85), Inches(6.85), Inches(11.6), Inches(.4),
    "Python standard library only. No framework, no dependencies, no lockfile.",
    size=13, color=MUTED)


# --------------------------------------------------------------- 7. UI
s_ = slide()
s = s_
header(s, "Prototype and UX", "Watch the investigation, step by step", "10%")
# docs/viewer.png predates both the OLED restyle and the SaaS shell rebuild, so
# it shows a UI that no longer exists. Rather than ship a stale screenshot, draw
# the CURRENT layout to scale. Replace this block with a real capture when one
# is taken.
PANEL, SIDE, CARDBG = RGBColor(0x0D,0x0D,0x0D), RGBColor(0x08,0x08,0x08), RGBColor(0x16,0x16,0x16)
NEON, ZINC, ZDIM = RGBColor(0x39,0xFF,0x14), RGBColor(0xE4,0xE4,0xE7), RGBColor(0x8A,0x8A,0x94)
px, py, pw, ph = Inches(.85), Inches(1.9), Inches(7.5), Inches(4.4)
sh = s_.shapes.add_shape(5, px, py, pw, ph)
sh.fill.solid(); sh.fill.fore_color.rgb = PANEL
sh.line.color.rgb = RGBColor(0x33,0x33,0x33); sh.shadow.inherit = False
sb = s_.shapes.add_shape(1, px, py, Inches(1.72), ph)
sb.fill.solid(); sb.fill.fore_color.rgb = SIDE; sb.line.fill.background()
sb.shadow.inherit = False
box(s_, px+Inches(.14), py+Inches(.13), Inches(1.5), Inches(.2), "SOC AGENT",
    size=8.5, color=ZINC, bold=True)
box(s_, px+Inches(.14), py+Inches(.42), Inches(1.5), Inches(.18), "SCENARIOS",
    size=6.5, color=ZDIM, bold=True)
names = [("1 False alarm","FAIL",GREEN),("2 True positive","SUCC",RED),
         ("3 Delayed evidence","SUCC",RED),("4 Human override","SUCC",RED),
         ("5 Correlation","SUCC",RED),("6 Tool failure","INC",AMBER),
         ("7 Configuration","INC",AMBER)]
yy = py+Inches(.66)
for i,(n,b,c) in enumerate(names):
    if i == 1:
        hl = s_.shapes.add_shape(5, px+Inches(.08), yy-Inches(.02), Inches(1.56), Inches(.26))
        hl.fill.solid(); hl.fill.fore_color.rgb = CARDBG
        hl.line.color.rgb = RGBColor(0x33,0x33,0x33); hl.shadow.inherit = False
    box(s_, px+Inches(.16), yy, Inches(1.05), Inches(.2), n, size=7,
        color=ZINC if i==1 else ZDIM)
    box(s_, px+Inches(1.24), yy, Inches(.36), Inches(.2), b, size=6, color=c, bold=True)
    yy += Inches(.30)
# KPI row
kx = px+Inches(1.86)
for lbl,val in [("OUTCOME","SUCCEEDED"),("CONFIDENCE","0.95"),("EVIDENCE","9"),("REFUSALS","1")]:
    k = s_.shapes.add_shape(5, kx, py+Inches(.18), Inches(1.3), Inches(.62))
    k.fill.solid(); k.fill.fore_color.rgb = CARDBG
    k.line.color.rgb = RGBColor(0x2A,0x2A,0x2A); k.shadow.inherit = False
    box(s_, kx+Inches(.09), py+Inches(.25), Inches(1.15), Inches(.16), lbl, size=6, color=ZDIM, bold=True)
    box(s_, kx+Inches(.09), py+Inches(.44), Inches(1.15), Inches(.22), val, size=9,
        color=RED if val=="SUCCEEDED" else ZINC, bold=True)
    kx += Inches(1.36)
# timeline cards, including the refusal
ty = py+Inches(.95)
tl = [("TOOL CALL","get_asset_info(asset_id='SRV-DB-02')",NEON,CARDBG),
      ("RESULT  OK","mysql 5.7.21 running",ZDIM,CARDBG),
      ("TOOL CALL","get_vulnerabilities(service_name='mysql')",NEON,CARDBG),
      ("RESULT  REJECTED","factor 'version_patched' claims the host is outside ALL ranges, but openssh was never looked up",RED,RGBColor(0x24,0x10,0x0F)),
      ("REASONING","I need to fix two issues. Let me check openssh CVEs.",ZINC,CARDBG),
      ("SCORING","base 0.50 -> raw 1.15 -> score 0.95  SUCCEEDED",AMBER,CARDBG)]
for lbl,txt,col,bg in tl:
    c = s_.shapes.add_shape(5, px+Inches(1.86), ty, Inches(5.45), Inches(.5))
    c.fill.solid(); c.fill.fore_color.rgb = bg
    c.line.color.rgb = RGBColor(0x2A,0x2A,0x2A); c.shadow.inherit = False
    box(s_, px+Inches(1.98), ty+Inches(.06), Inches(5.2), Inches(.16), lbl, size=6, color=col, bold=True)
    box(s_, px+Inches(1.98), ty+Inches(.23), Inches(5.2), Inches(.24), txt, size=7,
        color=ZINC, font="Consolas" if "get_" in txt or "base" in txt else "Segoe UI")
    ty += Inches(.56)

feats = [
    ("Every step, in order", "Each tool call with the reason the agent gave BEFORE making it."),
    ("Refusals shown inline", "The guard rejection and the correction are both steps in the chain."),
    ("Reconsiderations forked", "Prior conclusion sits beside the new one. Never overwritten."),
    ("Replay, not live", "A live loop on stage can hang or rate-limit. Determinism over spectacle."),
]
y = Inches(1.9)
for t, d in feats:
    card(s, Inches(8.6), y, Inches(3.85), Inches(1.02), accent=ORNG)
    box(s, Inches(8.92), y + Inches(.14), Inches(3.4), Inches(.3), t, size=13, color=INK, bold=True)
    box(s, Inches(8.92), y + Inches(.46), Inches(3.4), Inches(.5), d, size=11, color=BODY)
    y += Inches(1.12)

box(s, Inches(.85), Inches(6.45), Inches(11.6), Inches(.5),
    "A separate plain-language site explains the product for a non-technical reader; the viewer is the technical artefact.",
    size=12.5, color=MUTED)

# --------------------------------------------------------------- 8. Guardrails
s = slide()
header(s, "Robustness and guardrails", "What stops it doing something stupid", "10%")
guards = [
    ("It cannot cite what it did not read",
     "A factor drawn from a lookup that returned no data is refused before it can ever reach the score."),
    ("It cannot claim ALL from SOME",
     "Saying a host is outside every affected range, having checked two of its three services, is refused."),
    ("It cannot hold both sides",
     "Declaring a finding and its negation together is refused."),
    ("It cannot contradict a sibling case",
     "Calling an asset clean over a window another case already concluded was breached is refused."),
]
y = Inches(1.9)
for t, d in guards:
    card(s, Inches(.85), y, Inches(7.4), Inches(.95), accent=ORNG)
    box(s, Inches(1.18), y + Inches(.13), Inches(6.8), Inches(.3), t, size=13.5, color=INK, bold=True)
    box(s, Inches(1.18), y + Inches(.46), Inches(6.8), Inches(.42), d, size=11.5, color=BODY)
    y += Inches(1.05)

box(s, Inches(.85), Inches(6.15), Inches(7.4), Inches(.85),
    "The guards judge the FORM of a claim, never the evidence. They never decide whether a version "
    "is in range; that comparison stays the agent's, and it is visible in the trace.",
    size=12, color=MUTED)

card(s, Inches(8.6), Inches(1.9), Inches(3.85), Inches(5.1), fill=WARM, accent=ORNG)
box(s, Inches(8.95), Inches(2.12), Inches(3.3), Inches(.3), "VERIFIED, NOT ASSERTED", size=11, color=ORNG, bold=True)
nums = [("105 / 105", "offline behavioural checks"),
        ("22 / 22", "guardrail checks"),
        ("51 / 51", "live checks across six scenarios"),
        ("1", "scenario left FAILING on purpose"),
        ("0", "refusals resolved by rewording")]
y = Inches(2.55)
for n, l in nums:
    box(s, Inches(8.95), y, Inches(3.3), Inches(.4), n, size=23, color=INK, bold=True, font="Georgia")
    box(s, Inches(8.95), y + Inches(.4), Inches(3.3), Inches(.35), l, size=10.5, color=MUTED)
    y += Inches(.9)

# --------------------------------------------------------------- 9. Conclusion
s = slide()
header(s, "Conclusion", "What it is, and where it goes")
card(s, Inches(.85), Inches(1.85), Inches(5.65), Inches(2.5))
box(s, Inches(1.18), Inches(2.05), Inches(5.0), Inches(.3), "WHAT WE BUILT", size=11, color=ORNG, bold=True)
box(s, Inches(1.18), Inches(2.42), Inches(5.05), Inches(1.8),
    "An agent that investigates a security alert the way an analyst would: "
    "forms a hypothesis, decides what evidence would falsify it, gathers, "
    "concludes with citations, acts when justified, and then checks that its "
    "own action actually took effect.", size=13, color=BODY)

card(s, Inches(6.8), Inches(1.85), Inches(5.65), Inches(2.5))
box(s, Inches(7.13), Inches(2.05), Inches(5.0), Inches(.3), "SCALING IT", size=11, color=ORNG, bold=True)
box(s, Inches(7.13), Inches(2.42), Inches(5.05), Inches(1.8),
    "The tools are already an interface, not an implementation. Point "
    "get_server_logs at a real SIEM, get_asset_info at a real CMDB and "
    "block_ip at a real firewall API, and the reasoning loop is unchanged. "
    "The sandbox boundary is a swap, not a rewrite.", size=13, color=BODY)

card(s, Inches(.85), Inches(4.55), Inches(11.6), Inches(1.35), fill=WARM, accent=ORNG)
box(s, Inches(1.2), Inches(4.75), Inches(11.0), Inches(.32),
    "THE LIMITATION WE LEFT VISIBLE", size=11, color=ORNG, bold=True)
box(s, Inches(1.2), Inches(5.1), Inches(11.0), Inches(.7),
    "Scenario 7 fails on purpose. The agent correctly works out that a database account had no privilege on the targeted "
    "table, and says so in its report, but the scoring model has no term for a configuration control, so the case stops "
    "short of a verdict. We built the factor, it failed its own gate, and we reverted it rather than ship a number we "
    "could not defend.", size=12.5, color=BODY)

box(s, Inches(.85), Inches(6.25), Inches(11.6), Inches(.5),
    "soc-agent-trace-viewer.vercel.app", size=17, color=ORNG, bold=True,
    font="Consolas", align=PP_ALIGN.CENTER)

prs.save("deck.pptx")
print("saved deck.pptx")
