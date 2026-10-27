"""Accessibility: every page has one h1, named controls, and live regions where things change."""

from __future__ import annotations

from html.parser import HTMLParser
from importlib import resources

from conftest import KEY, Clock, token_from

from kinlock import pages
from kinlock.engine import Engine
from kinlock_authority import Action

VOID = {"input", "br", "meta", "img", "hr", "link"}


class Tree(HTMLParser):
    """A small DOM: enough to compute headings, accessible names and live regions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = {"tag": "#root", "attrs": {}, "kids": [], "text": []}
        self.stack = [self.root]
        self.ids: dict[str, dict] = {}

    def handle_starttag(self, tag, attrs):
        node = {"tag": tag, "attrs": {k: (v or "") for k, v in attrs}, "kids": [], "text": [], "parent": self.stack[-1]}
        self.stack[-1]["kids"].append(node)
        if "id" in node["attrs"]:
            self.ids[node["attrs"]["id"]] = node
        if tag not in VOID:
            self.stack.append(node)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if self.stack[-1]["tag"] not in ("script", "style"):
            self.stack[-1]["kids"].append(data)

    def all(self, node=None):
        node = node or self.root
        for k in node["kids"]:
            if isinstance(k, dict):
                yield k
                yield from self.all(k)


def text(node) -> str:
    return " ".join("".join(k if isinstance(k, str) else text(k) for k in node["kids"]).split())


def name(tree: Tree, node) -> str:
    a = node["attrs"]
    if a.get("aria-label"):
        return a["aria-label"]
    if a.get("aria-labelledby"):
        return " ".join(text(tree.ids[i]) for i in a["aria-labelledby"].split())
    if node["tag"] in ("input", "textarea", "select"):
        if a.get("id"):
            for lab in tree.all():
                if lab["tag"] == "label" and lab["attrs"].get("for") == a["id"]:
                    return text(lab)
        p = node.get("parent")
        while p is not None:
            if p["tag"] == "label":
                return text(p)
            p = p.get("parent")
        return a.get("title", "")
    return text(node) or a.get("title", "")


def parse(html: str) -> Tree:
    t = Tree()
    t.feed(html)
    return t


def check_page(html: str) -> Tree:
    t = parse(html)
    assert t.root["kids"], "empty page"
    html_el = next(n for n in t.all() if n["tag"] == "html")
    assert html_el["attrs"].get("lang") == "en"
    h1 = [n for n in t.all() if n["tag"] == "h1"]
    assert len(h1) == 1 and text(h1[0]), [text(h) for h in h1]
    for n in t.all():
        a = n["attrs"]
        interactive = n["tag"] in ("button", "a", "select", "textarea") or (n["tag"] == "input" and a.get("type") != "hidden") or a.get("role") == "button"
        if interactive:
            assert name(t, n).strip(), f"unnamed {n['tag']} {a}"
        if a.get("role") == "button":
            assert a.get("tabindex") == "0", "a role=button must be focusable"
        if a.get("aria-labelledby"):
            assert all(i in t.ids for i in a["aria-labelledby"].split())
    return t


def live(t: Tree, node_id: str) -> bool:
    n = t.ids[node_id]
    return n["attrs"].get("aria-live") in ("polite", "assertive") or n["attrs"].get("role") in ("status", "alert", "log")


def test_simulator_page_is_accessible():
    html = resources.files("kinlock").joinpath("sim.html").read_text()
    t = check_page(html)
    for region in ("log", "decision", "lock", "attackout", "push"):
        assert live(t, region), region
    assert name(t, t.ids["q"]) == "Message to Alexa"
    assert name(t, t.ids["ring"]) == "Tap to speak to Alexa"
    sections = [n for n in t.all() if n["tag"] == "section"]
    assert sections and all(name(t, s) for s in sections)
    assert "onkeydown" in html  # the speak button works from the keyboard


def snapshot_with_everything(data_dir, clock: Clock):
    eng = Engine(data_dir, KEY, "http://kinlock.test", clock=clock)
    r = eng.request(Action("r-1", "purchase", 84999, "TechZone", "electronics", ("a laptop",)))
    eng.contact_decide(token_from(r.link), eng.contact_view(token_from(r.link))["digest"], True)
    eng.request(Action("r-2", "purchase", 84999, "TechZone", "electronics", ("a laptop",)))
    return eng


def test_owner_page_is_accessible(data_dir, clock: Clock):
    eng = snapshot_with_everything(data_dir, clock)
    t = check_page(pages.owner_page(eng.snapshot(), "csrf", "Done."))
    buttons = [name(t, n) for n in t.all() if n["tag"] == "button"]
    assert "Approve $849.99 at TechZone" in buttons and "Deny $849.99 at TechZone" in buttons
    assert name(t, t.ids["contact-decisions"]) == "What your trusted contact decided"
    assert any(n["attrs"].get("role") == "status" and "Done." in text(n) for n in t.all())
    assert all(th["attrs"].get("scope") == "col" for th in t.all() if th["tag"] == "th")


def test_other_pages_are_accessible(data_dir, clock: Clock):
    eng = snapshot_with_everything(data_dir, clock)
    check_page(pages.owner_signin())
    t = check_page(pages.owner_signin(error=True))
    assert any(n["attrs"].get("role") == "alert" for n in t.all())
    assert name(t, next(n for n in t.all() if n["tag"] == "input")) == "Passphrase"
    check_page(pages.receipts_page(eng))
    tok = token_from(eng.request(Action("r-3", "purchase", 84999, "TechZone", "electronics", ("a laptop",))).link)
    check_page(pages.contact_page(tok, eng.contact_view(tok)))
    res = eng.contact_decide(tok, eng.contact_view(tok)["digest"], False)
    t = check_page(pages.contact_result(res, None))
    assert any(n["attrs"].get("role") == "status" for n in t.all())
    check_page(pages.contact_page("gone", {"open": False, "action": None}))
