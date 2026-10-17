package webui

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Exercise the shipped modules together: a layout change moves windows between
// containers, while hide/show and tab clicks must keep their visibility and
// selection consistent. Testing those functions individually misses the bug.
func TestSessionTabbarStateTransitions(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH; cannot exercise session tab bar transitions")
	}
	dir := t.TempDir()
	for _, name := range []string{"util.js", "shell-windows.js"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(readAssetLF(t, "static/js/"+name)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	script := `
const fs = require('fs');
const vm = require('vm');
const path = require('path');
const dir = path.dirname(process.argv[1]);
const sources = ['util.js', 'shell-windows.js'].map(name => fs.readFileSync(path.join(dir, name), 'utf8'));

// Only the browser's DOM and rendering boundaries are simulated. All state
// transitions, tab listeners, window lookup and z-order use the real modules.
function element(id = '', className = '') {
  const node = { id, className, children: [], parentNode: null, attrs: {}, listeners: {},
    style: { setProperty(k, v) { this[k] = v; } },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return this.attrs[k] == null ? null : this.attrs[k]; },
    addEventListener(k, fn) { this.listeners[k] = fn; },
    appendChild(child) {
      if (child.parentNode) child.parentNode.removeChild(child);
      this.children.push(child); child.parentNode = this;
      return child;
    },
    removeChild(child) {
      this.children = this.children.filter(x => x !== child); child.parentNode = null;
    },
    remove() { if (this.parentNode) this.parentNode.removeChild(this); },
    querySelectorAll(selector) {
      const out = [];
      const matches = child => selector.startsWith('.') && selector.slice(1).split('.').every(c => child.classList.contains(c));
      function visit(parent) {
        parent.children.forEach(child => { if (matches(child)) out.push(child); visit(child); });
      }
      visit(this); return out;
    },
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; },
    getBoundingClientRect() { return { left: 100, top: 100, width: 640, height: 480, bottom: 580 }; },
    scrollIntoView() {}
  };
  const classes = () => new Set(node.className.split(/\s+/).filter(Boolean));
  node.classList = {
    contains(c) { return classes().has(c); },
    add(...cs) { const all = classes(); cs.forEach(c => all.add(c)); node.className = [...all].join(' '); },
    remove(...cs) { const all = classes(); cs.forEach(c => all.delete(c)); node.className = [...all].join(' '); },
    toggle(c, force) {
      const on = force === undefined ? !this.contains(c) : force;
      on ? this.add(c) : this.remove(c); return on;
    }
  };
  Object.defineProperty(node, 'innerHTML', { set(html) {
    node.children.slice().forEach(child => node.removeChild(child));
    for (const match of html.matchAll(/class="([^"]+)"/g)) node.appendChild(element('', match[1]));
  } });
  return node;
}

function fixture() {
  const body = element(), ids = {};
  for (const id of ['shell-windows-container', 'pane-workspace', 'pane-grid', 'session-tabbar',
    'session-tabs-scroll', 'session-tabbar-actions', 'session-tabbar-grip']) ids[id] = element(id);
  body.appendChild(ids['shell-windows-container']);
  body.appendChild(ids['pane-workspace']);
  ids['pane-workspace'].appendChild(ids['pane-grid']);
  body.appendChild(ids['session-tabbar']);
  ['session-tabs-scroll', 'session-tabbar-actions', 'session-tabbar-grip'].forEach(id => ids['session-tabbar'].appendChild(ids[id]));
  const document = {
    body, documentElement: element(),
    getElementById(id) {
      if (ids[id]) return ids[id];
      function find(node) { if (node.id === id) return node; for (const child of node.children) { const found = find(child); if (found) return found; } }
      return find(body) || null;
    },
    createElement() { return element(); },
    querySelector(s) { return body.querySelector(s); },
    querySelectorAll(s) { return body.querySelectorAll(s); },
    addEventListener() {}
  };
  const openRequests = [];
  const ctx = { document, console, innerWidth: 1280, innerHeight: 800,
    localStorage: { getItem() { return null; }, setItem() {} },
    matchMedia() { return { matches: false }; }, addEventListener() {},
    requestAnimationFrame() { return 1; }, applyI18n() {}, onLangChange() {}, t: key => key,
    openShellWindow(label, sid, pos, opts) { openRequests.push({ label, sid, pos, opts }); },
    lockWindowReadonly(w) { w.readonlyApplied = true; }
  };
  ctx.window = ctx;
  vm.createContext(ctx);
  sources.forEach(src => vm.runInContext(src, ctx));
  function win(n, sid) {
    const w = element('shell-window-' + n, 'shell-window');
    w._sid = sid; w._placeholder = sid === null; w._pendingConnName = 'fixture-' + n;
    w._connName = sid === null ? '' : 'fixture-' + n;
    w._channels = {}; w._term = { focus() { w.focused = true; } };
    ids['shell-windows-container'].appendChild(w);
    ctx.bringShellWindowToFront(w);
    return w;
  }
  const tabs = () => ids['session-tabs-scroll'].children;
  const active = () => tabs().filter(tab => tab.getAttribute('aria-selected') === 'true').map(tab => tab._win.id);
  const visible = w => !w.classList.contains('win-hidden') && !w.classList.contains('win-minimized') &&
    (w.parentNode !== ids['pane-grid'] || ids['pane-workspace'].classList.contains('open'));
  function click(w) { tabs().find(tab => tab._win === w).listeners.click({ target: { closest() { return null; } } }); }
  return { ctx, ids, document, win, active, visible, click, openRequests };
}

let failures = 0;
function eq(label, got, want) {
  if (JSON.stringify(got) !== JSON.stringify(want)) { console.log('FAIL ' + label + ': got ' + JSON.stringify(got) + ', want ' + JSON.stringify(want)); failures++; }
}
function checkHidden(f, windows, label) {
  eq(label + ': windows hidden', windows.map(f.visible), windows.map(() => false));
  eq(label + ': workspace closed', f.ids['pane-workspace'].classList.contains('open'), false);
  eq(label + ': aria hidden', f.ids['pane-workspace'].getAttribute('aria-hidden'), 'true');
  eq(label + ': no active tab', f.active(), []);
  eq(label + ': show action', f.document.getElementById('session-tabbar-toggle').title, 'win.showAll');
}

// Run both directions and repeated switches: stale .win-hidden can survive
// moving to the grid, while a hidden grid's children have no such class yet.
for (const startMode of ['float', 'tile']) {
  const f = fixture(), a = f.win(1, 'session-one'), b = f.win(2, 'session-two');
  f.ctx.setLayoutMode(startMode);
  f.ctx.hideAllWindows();
  checkHidden(f, [a, b], startMode + ' hidden');
  for (const mode of ['tile', 'float', 'tile']) {
    f.ctx.setLayoutMode(mode);
    checkHidden(f, [a, b], startMode + ' hidden -> ' + mode);
  }
  f.ctx.showAllWindows();
  eq(startMode + ': show reveals both panes', [a, b].map(f.visible), [true, true]);
  eq(startMode + ': show restores active tab', f.active().length, 1);
  f.ctx.setLayoutMode('float');
  eq(startMode + ': shown panes remain visible as floats', [a, b].map(f.visible), [true, true]);
}

// A tab owns a window before the server assigns an id. Two concurrent dials
// both have a null session id; neither may accidentally select the other.
for (const mode of ['float', 'tile']) {
  const f = fixture(), a = f.win(1, null), b = f.win(2, null);
  eq(mode + ': a null session id is not a window identity', f.ctx.getShellWindowBySid(null), null);
  f.ctx.setLayoutMode(mode);
  f.click(a); f.click(b);
  eq(mode + ': second connecting tab targets its own window', f.active(), [b.id]);
  f.ctx.minimizeShellWindow(b);
  b.classList.add('shell-window-collapsed'); b._savedH = '480px';
  f.ctx.hideAllWindows();
  f.click(b);
  eq(mode + ': clicking hidden pending tab reveals it', f.visible(b), true);
  eq(mode + ': pending tab restores minimize', b._minimized, false);
  eq(mode + ': pending tab expands collapse', b.classList.contains('shell-window-collapsed'), false);
  eq(mode + ': pending tab retains correct selection', f.active(), [b.id]);
  eq(mode + ': pending tab focuses terminal', b.focused, true);
  eq(mode + ': pending tabs do not open duplicate windows', f.openRequests, []);
}

// Minimize is per window, unlike hide-all: showing all must not unminimize a
// different window. Session-based entry points must retain their old behavior.
for (const mode of ['float', 'tile']) {
  const f = fixture(), a = f.win(1, 'session-one'), b = f.win(2, 'session-two');
  f.ctx.setLayoutMode(mode); f.ctx.minimizeShellWindow(a); f.ctx.hideAllWindows(); f.ctx.showAllWindows();
  eq(mode + ': show-all preserves individual minimize', f.visible(a), false);
  eq(mode + ': show-all restores the other window', f.visible(b), true);
  f.ctx.focusSessionWindow('fixture-1', 'session-one', null, { readOnly: true });
  eq(mode + ': session lookup restores and selects window', f.active(), [a.id]);
  eq(mode + ': session lookup applies read-only', a.readonlyApplied, true);
  f.ctx.focusSessionWindow('fixture-new', 'session-new', null, { readOnly: true });
  eq(mode + ': unknown session opens with original options', f.openRequests,
    [{ label: 'fixture-new', sid: 'session-new', pos: null, opts: { readOnly: true } }]);
}
if (failures) process.exit(1);
console.log('PASS session tab bar state transitions');
`
	probe := filepath.Join(dir, "probe.js")
	if err := os.WriteFile(probe, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, probe).CombinedOutput(); err != nil {
		t.Fatalf("session tab bar state transitions: %v\n%s", err, out)
	}
}
