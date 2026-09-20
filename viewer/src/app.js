/* AEGIS trace viewer.
   Reads window.__AEGIS__ (embedded by `python -m aegis.trace.viewer`) and renders
   one decision at a time: what the agent proposed, what influenced it, how much
   authority that influence could grant, and what happened next.
   Plain DOM, no framework, no network. */

(function () {
  "use strict";

  var DATA = window.__AEGIS__ || { runs: [], summary: {}, meta: {} };
  var RUNS = DATA.runs || [];
  var RUN_BY_ID = {};
  RUNS.forEach(function (r) { RUN_BY_ID[r.run_id] = r; });

  /* ------------------------------------------------------------ constants */

  var TRUST = [
    { id: "system_policy",        rank: 1, band: "commit",  short: "policy" },
    { id: "authenticated_user",   rank: 2, band: "commit",  short: "user" },
    { id: "trusted_internal",     rank: 3, band: "prepare", short: "internal" },
    { id: "untrusted_internal",   rank: 4, band: "prepare", short: "internal (unverified)" },
    { id: "untrusted_external",   rank: 5, band: "read",    short: "external" },
    { id: "adversary_controlled", rank: 6, band: "read",    short: "adversary" }
  ];
  var TRUST_BY_ID = {};
  TRUST.forEach(function (t) { TRUST_BY_ID[t.id] = t; });

  var AUTHORITY = ["none", "read", "prepare", "commit"];
  var AUTHORITY_BLURB = {
    none: "inert",
    read: "observe only",
    prepare: "reversible drafts",
    commit: "irreversible, externally visible"
  };

  var DECISIONS = ["allow", "rewrite", "escalate", "block"];
  var DECISION_TEXT = {
    allow: "Allowed",
    rewrite: "Rewritten",
    escalate: "Escalated",
    block: "Blocked"
  };

  var ICONS = {
    check: ["M2.8 8.4l3.3 3.3L13.2 4.6"],
    slash: ["M8 2.4a5.6 5.6 0 100 11.2A5.6 5.6 0 008 2.4z", "M4.1 11.9L11.9 4.1"],
    arrowUp: ["M8 13.4V3.4", "M4.2 7.2L8 3.4l3.8 3.8"],
    pen: ["M3 11.1l6.5-6.5 2.9 2.9-6.5 6.5H3z", "M9.5 4.6l1.4-1.4 2.9 2.9-1.4 1.4"],
    warn: ["M8 2.5l5.9 10.6H2.1z", "M8 6.6v3.1", "M8 11.2v.1"],
    cross: ["M4 4l8 8", "M12 4l-8 8"],
    dot: ["M8 5.4a2.6 2.6 0 100 5.2 2.6 2.6 0 000-5.2z"],
    arrowRight: ["M2.8 8h10.4", "M9.6 4.4L13.2 8l-3.6 3.6"]
  };
  var DECISION_ICON = { allow: "check", block: "slash", escalate: "arrowUp", rewrite: "pen" };

  /* -------------------------------------------------------------- helpers */

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function icon(name, size) {
    var paths = ICONS[name] || ICONS.dot;
    var svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", "none");
    if (size) { svg.setAttribute("width", size); svg.setAttribute("height", size); }
    paths.forEach(function (d) {
      var p = document.createElementNS("http://www.w3.org/2000/svg", "path");
      p.setAttribute("d", d);
      p.setAttribute("stroke", "currentColor");
      p.setAttribute("stroke-width", "1.7");
      p.setAttribute("stroke-linecap", "round");
      p.setAttribute("stroke-linejoin", "round");
      p.setAttribute("fill", "none");
      svg.appendChild(p);
    });
    return svg;
  }

  function badge(decision, large) {
    var node = el("span", "badge d-" + decision + (large ? " lg" : ""));
    node.appendChild(icon(DECISION_ICON[decision] || "dot"));
    node.appendChild(el("span", null, decision));
    return node;
  }

  function pill(text, tone, iconName) {
    var node = el("span", "pill" + (tone ? " " + tone : ""));
    if (iconName) node.appendChild(icon(iconName));
    node.appendChild(el("span", null, text));
    return node;
  }

  function num(value, digits) {
    if (value === null || value === undefined || isNaN(value)) return "n/a";
    return Number(value).toFixed(digits === undefined ? 2 : digits);
  }

  function pct(value) {
    if (value === null || value === undefined) return "n/a";
    var scaled = Number(value) * 100;
    if (scaled > 0 && scaled < 10) return scaled.toFixed(1) + "%";
    return scaled.toFixed(0) + "%";
  }

  function shortTime(stamp) {
    if (!stamp) return "\u2014";
    return String(stamp).replace("T", " ").slice(0, 19) + " UTC";
  }

  function clamp01(v) { return Math.max(0, Math.min(1, Number(v) || 0)); }

  function fmtValue(v) {
    if (v === null || v === undefined) return "null";
    if (typeof v === "string") return v;
    try { return JSON.stringify(v); } catch (e) { return String(v); }
  }

  function titleize(text) {
    return String(text || "").replace(/[_-]+/g, " ");
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  /* ---------------------------------------------------------------- state */

  var state = {
    runId: null,
    stepId: null,
    view: "run",
    presenter: false,
    filters: { decision: null, reason: null, domain: null, query: "" }
  };

  function currentRun() { return RUN_BY_ID[state.runId] || null; }

  function currentStep() {
    var run = currentRun();
    if (!run) return null;
    for (var i = 0; i < run.steps.length; i++) {
      if (run.steps[i].step_id === state.stepId) return run.steps[i];
    }
    return run.steps[0] || null;
  }

  /* -------------------------------------------------------------- routing */

  function writeHash() {
    var hash = state.view === "summary"
      ? "#/summary"
      : "#/run/" + encodeURIComponent(state.runId || "") + "/step/" + (state.stepId === null ? "" : state.stepId);
    if (window.location.hash !== hash) {
      history.replaceState(null, "", hash);
    }
  }

  function readHash() {
    var hash = decodeURIComponent(window.location.hash.replace(/^#\/?/, ""));
    if (!hash) return false;
    if (hash.indexOf("summary") === 0) { state.view = "summary"; return true; }
    var m = hash.match(/^run\/(.+?)(?:\/step\/(\d+))?$/);
    if (!m) return false;
    var run = RUN_BY_ID[m[1]];
    if (!run) return false;
    state.view = "run";
    state.runId = run.run_id;
    state.stepId = m[2] ? parseInt(m[2], 10) : (run.steps[0] ? run.steps[0].step_id : null);
    return true;
  }

  /* ------------------------------------------------------------ rail: runs */

  function visibleRuns() {
    var f = state.filters;
    var q = f.query.trim().toLowerCase();
    return RUNS.filter(function (run) {
      if (f.domain && run.domain !== f.domain) return false;
      if (f.decision && !(run.counts[f.decision] > 0)) return false;
      if (f.reason && (run.reason_codes || []).indexOf(f.reason) < 0) return false;
      if (q) {
        var hay = (run.run_id + " " + run.scenario_id + " " + run.user_goal + " " + (run.attack_family || "")).toLowerCase();
        if (hay.indexOf(q) < 0) return false;
      }
      return true;
    });
  }

  function runShape(run) {
    var wrap = el("span", "shape");
    wrap.setAttribute("role", "img");
    var counts = run.counts || {};
    wrap.setAttribute("aria-label",
      DECISIONS.map(function (d) { return (counts[d] || 0) + " " + d; }).join(", "));
    run.steps.forEach(function (step) {
      wrap.appendChild(el("i", "d-" + step.decision));
    });
    return wrap;
  }

  function renderRail() {
    var list = document.getElementById("run-list");
    clear(list);
    var runs = visibleRuns();
    if (!runs.length) {
      list.appendChild(el("p", "empty", "No run matches these filters."));
      return;
    }
    var domain = null;
    runs.forEach(function (run) {
      if (run.domain !== domain) {
        domain = run.domain;
        list.appendChild(el("div", "group-label", domain));
      }
      var item = el("button", "run-item");
      item.type = "button";
      item.title = run.run_id;
      item.setAttribute("aria-current", run.run_id === state.runId ? "true" : "false");
      var shortName = run.scenario_id.indexOf(run.domain + "_") === 0
        ? run.scenario_id.slice(run.domain.length + 1)
        : run.scenario_id;
      item.appendChild(el("span", "run-name", shortName));
      var meta = el("div", "run-meta");
      meta.appendChild(runShape(run));
      var fam = run.attack_family || "unknown";
      meta.appendChild(el("span", "tag " + (fam === "benign" ? "benign" : "attack"),
        fam === "benign" ? "benign" : titleize(fam)));
      if (run.outcome) {
        if (run.outcome.attack_present && run.outcome.attack_success === false) {
          meta.appendChild(el("span", "tag benign", "attack failed"));
        } else if (run.outcome.attack_success) {
          meta.appendChild(el("span", "tag attack", "attack SUCCEEDED"));
        }
        if (run.outcome.task_success === false) {
          meta.appendChild(el("span", "tag attack", "task failed"));
        }
      }
      meta.appendChild(el("span", null, run.steps.length + " steps"));
      (run.problems || []).forEach(function (problem) {
        meta.appendChild(el("span", "tag " + (problem.level === "error" ? "attack" : ""),
          problem.code === "NO_OUTCOME" ? "no outcome" : titleize(problem.code).toLowerCase()));
      });
      item.appendChild(meta);
      item.addEventListener("click", function () {
        selectRun(run.run_id, null);
        document.body.classList.remove("rail-open");
      });
      list.appendChild(item);
    });
  }

  function renderFilters() {
    var domains = {};
    RUNS.forEach(function (r) { domains[r.domain] = true; });
    var box = document.getElementById("domain-filters");
    clear(box);
    Object.keys(domains).sort().forEach(function (d) {
      var chip = el("button", "chip", d);
      chip.type = "button";
      chip.setAttribute("aria-pressed", state.filters.domain === d ? "true" : "false");
      chip.addEventListener("click", function () {
        state.filters.domain = state.filters.domain === d ? null : d;
        renderFilters(); renderRail();
      });
      box.appendChild(chip);
    });

    var dbox = document.getElementById("decision-filters");
    clear(dbox);
    DECISIONS.forEach(function (d) {
      var chip = el("button", "chip", d);
      chip.type = "button";
      chip.setAttribute("aria-pressed", state.filters.decision === d ? "true" : "false");
      chip.addEventListener("click", function () {
        state.filters.decision = state.filters.decision === d ? null : d;
        renderFilters(); renderRail(); renderSteps();
      });
      dbox.appendChild(chip);
    });

    var rbox = document.getElementById("reason-filter");
    clear(rbox);
    if (state.filters.reason) {
      var chip = el("button", "chip", "reason: " + state.filters.reason);
      chip.type = "button";
      chip.setAttribute("aria-pressed", "true");
      chip.addEventListener("click", function () {
        state.filters.reason = null;
        renderFilters(); renderRail(); renderSteps();
      });
      rbox.appendChild(chip);
    }
  }

  /* ------------------------------------------------------- column: steps */

  function outcomePills(run) {
    var strip = el("div", "outcome-strip");
    var o = run.outcome;
    if (!o) {
      strip.appendChild(pill("outcome not joined", null, "dot"));
      return strip;
    }
    strip.appendChild(pill(
      o.task_success ? "task completed" : "task failed",
      o.task_success ? "good" : "bad",
      o.task_success ? "check" : "cross"));
    if (o.attack_present) {
      strip.appendChild(pill(
        o.attack_success ? "attack succeeded" : "attack failed",
        o.attack_success ? "bad" : "good",
        o.attack_success ? "cross" : "check"));
    } else {
      strip.appendChild(pill("no attack (benign)", null, "dot"));
    }
    if (o.critical_violation) strip.appendChild(pill("critical violation", "bad", "warn"));
    if (o.hard_negative) strip.appendChild(pill("hard negative", "warn", "dot"));
    if (o.termination) strip.appendChild(pill(titleize(o.termination), null, "dot"));
    return strip;
  }

  function stepMatchesFilters(step) {
    var f = state.filters;
    if (f.decision && step.decision !== f.decision) return false;
    if (f.reason && (step.reason_codes || []).indexOf(f.reason) < 0) return false;
    return true;
  }

  function renderSteps() {
    var head = document.getElementById("run-head");
    var list = document.getElementById("step-list");
    clear(head); clear(list);
    var run = currentRun();
    if (!run) {
      list.appendChild(el("p", "empty", "Pick a run."));
      return;
    }

    var title = el("h2", null, run.scenario_id);
    head.appendChild(title);
    var sub = el("div", "run-meta");
    sub.appendChild(el("span", "tag", run.domain));
    sub.appendChild(el("span", "tag " + (run.attack_family === "benign" ? "benign" : "attack"),
      run.attack_family === "benign" ? "benign task" : titleize(run.attack_family)));
    sub.appendChild(el("span", null, "peak risk " + num(run.max_risk)));
    head.appendChild(sub);

    var goal = el("div", "goal");
    goal.appendChild(el("span", "goal-label", "User goal"));
    goal.appendChild(document.createTextNode(run.user_goal || "—"));
    head.appendChild(goal);
    head.appendChild(outcomePills(run));

    var shown = 0;
    run.steps.forEach(function (step) {
      if (!stepMatchesFilters(step)) return;
      shown++;
      var item = el("button", "step-item");
      item.type = "button";
      item.setAttribute("aria-current", step.step_id === state.stepId ? "true" : "false");
      item.appendChild(el("span", "step-num", String(step.step_id)));
      var main = el("div", "step-main");
      var label = step.action && step.action.tool
        ? step.action.tool
        : (step.action ? step.action.type : "action");
      main.appendChild(el("div", "step-tool", label));
      var line = el("div", "step-line");
      line.appendChild(badge(step.decision));
      var meter = el("span", "meter");
      var fill = el("span", "d-" + step.decision);
      fill.style.width = (clamp01(step.risk_score) * 100).toFixed(1) + "%";
      meter.appendChild(fill);
      line.appendChild(meter);
      line.appendChild(el("span", "risk-num", num(step.risk_score)));
      main.appendChild(line);
      item.appendChild(main);
      item.addEventListener("click", function () { selectStep(step.step_id); });
      list.appendChild(item);
    });
    if (!shown) list.appendChild(el("p", "empty", "No step in this run matches the filters."));
  }

  /* ------------------------------------------------------ detail sections */

  function sectionCard(title) {
    var card = el("section", "card");
    card.appendChild(el("h3", null, title));
    return card;
  }

  function riskGauge(step) {
    var thresholds = (step.monitor && step.monitor.thresholds) || {};
    var esc = typeof thresholds.escalate_at === "number" ? thresholds.escalate_at : 0.38;
    var blk = typeof thresholds.block_at === "number" ? thresholds.block_at : 0.7;

    var wrap = el("div", "gauge");
    var readout = el("div", "gauge-readout");
    [["risk", num(step.risk_score)], ["confidence", num(step.confidence)],
     ["latency", num(step.latency_ms, 2) + " ms"]].forEach(function (pair) {
      var group = el("div");
      group.appendChild(el("div", "readout-value", pair[1]));
      group.appendChild(el("div", "readout-label", pair[0]));
      readout.appendChild(group);
    });
    wrap.appendChild(readout);

    var track = el("div", "gauge-track");
    var zones = [
      ["allow", 0, esc, "allow"],
      ["escalate", esc, blk, "escalate"],
      ["block", blk, 1, "block"]
    ];
    zones.forEach(function (z) {
      var zone = el("div", "zone " + z[0]);
      zone.style.left = (z[1] * 100) + "%";
      zone.style.width = ((z[2] - z[1]) * 100) + "%";
      var label = el("span", "zone-label", z[3]);
      zone.appendChild(label);
      track.appendChild(zone);
    });
    var marker = el("div", "gauge-marker");
    marker.style.left = "calc(" + (clamp01(step.risk_score) * 100) + "% - 1.5px)";
    marker.title = "risk " + num(step.risk_score, 4);
    track.appendChild(marker);
    wrap.appendChild(track);

    var scale = el("div", "gauge-scale");
    scale.appendChild(el("span", null, "0.00"));
    scale.appendChild(el("span", null, "escalate at " + num(esc)));
    scale.appendChild(el("span", null, "block at " + num(blk)));
    scale.appendChild(el("span", null, "1.00"));
    wrap.appendChild(scale);
    return wrap;
  }

  function headlineCard(run, step) {
    var card = el("section", "headline");
    var top = el("div", "headline-top");
    top.appendChild(badge(step.decision, true));
    top.appendChild(el("span", "headline-step", "step " + step.step_id + " of " + run.steps.length));
    var label = step.action && step.action.tool ? step.action.tool : (step.action ? step.action.type : "action");
    top.appendChild(el("span", "headline-tool", label));
    if (step.action && step.action.tool) {
      top.appendChild(el("span", "tag", step.action.type));
    }
    card.appendChild(top);

    card.appendChild(el("p", "explanation", step.explanation || DECISION_TEXT[step.decision] || ""));

    var codes = el("div", "codes");
    (step.reason_codes || []).forEach(function (code) {
      var chip = el("button", "code" + (step.decision === "block" ? " hot" : ""), code);
      chip.type = "button";
      chip.title = "Filter every run and step carrying " + code;
      chip.addEventListener("click", function () {
        state.filters.reason = state.filters.reason === code ? null : code;
        renderFilters(); renderRail(); renderSteps();
      });
      codes.appendChild(chip);
    });
    if (!(step.reason_codes || []).length) codes.appendChild(el("span", "code", "no reason codes"));
    card.appendChild(codes);
    card.appendChild(riskGauge(step));
    return card;
  }

  function diffNodes(before, after) {
    var frag = document.createDocumentFragment();
    var a = String(before || ""), b = String(after || "");
    var start = 0;
    while (start < a.length && start < b.length && a[start] === b[start]) start++;
    var endA = a.length, endB = b.length;
    while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) { endA--; endB--; }
    if (start) frag.appendChild(document.createTextNode(a.slice(0, start)));
    if (endA > start) {
      var del = el("span", "diff-del", a.slice(start, endA));
      frag.appendChild(del);
    }
    if (endB > start) {
      var ins = el("span", "diff-ins", b.slice(start, endB));
      frag.appendChild(ins);
    }
    if (endA < a.length) frag.appendChild(document.createTextNode(a.slice(endA)));
    return frag;
  }

  function actionCard(step) {
    var card = sectionCard("Candidate action");
    var action = step.action || {};
    var grid = el("div", "kv-grid");
    [["type", action.type], ["tool", action.tool || "—"],
     ["final", action.final ? "yes" : "no"]].forEach(function (pair) {
      var kv = el("dl", "kv");
      kv.appendChild(el("dt", null, pair[0]));
      kv.appendChild(el("dd", null, String(pair[1])));
      grid.appendChild(kv);
    });
    card.appendChild(grid);

    var args = action.arguments || {};
    var keys = Object.keys(args);
    if (keys.length) {
      card.appendChild(el("h3", null, "Arguments"));
      var box = el("div", "args");
      keys.forEach(function (key) {
        var row = el("div", "arg-row");
        row.appendChild(el("span", "arg-key", key));
        row.appendChild(el("span", "arg-val", fmtValue(args[key])));
        box.appendChild(row);
      });
      card.appendChild(box);
    }
    if (action.content) {
      card.appendChild(el("h3", null, "Content"));
      card.appendChild(el("div", "block-text", action.content));
    }

    if (step.rewritten_action) {
      card.appendChild(el("h3", null, "Rewritten by AEGIS"));
      var legend = el("div", "diff-legend");
      var l1 = el("span"); l1.appendChild(el("span", "diff-del", "removed")); legend.appendChild(l1);
      var l2 = el("span"); l2.appendChild(el("span", "diff-ins", "kept / added")); legend.appendChild(l2);
      card.appendChild(legend);
      var body = el("div", "block-text");
      var before = action.content !== undefined && action.content !== null
        ? String(action.content) : fmtValue(action.arguments);
      var after = step.rewritten_action.content !== undefined && step.rewritten_action.content !== null
        ? String(step.rewritten_action.content) : fmtValue(step.rewritten_action.arguments);
      body.appendChild(diffNodes(before, after));
      card.appendChild(body);
      card.appendChild(el("p", "hint",
        "The substance is kept; the instruction embedded in untrusted text is removed."));
    }

    if (step.observation && step.observation.excerpt) {
      card.appendChild(el("h3", null, "Observation this step read"));
      var obs = el("div", "block-text", step.observation.excerpt);
      card.appendChild(obs);
      card.appendChild(el("p", "hint", "kind: " + (step.observation.kind || "—") +
        " · provenance: " + ((step.observation.provenance_ids || []).join(", ") || "none")));
    }
    return card;
  }

  function authorityCard(step) {
    var card = sectionCard("Authority verdict");
    var authority = step.authority || {};
    var taint = step.taint || {};
    var required = authority.required || "none";
    var available = authority.available || "commit";
    var satisfied = authority.satisfied !== false;
    var actionTaint = taint.action_taint;
    var trust = TRUST_BY_ID[actionTaint];

    var TRUST_CAP = { commit: "commit", prepare: "prepare", read: "read" };
    var trustCap = trust ? TRUST_CAP[trust.band] : null;

    var cap = el("p", "cap-line");
    cap.appendChild(document.createTextNode("Least-trusted influence "));
    if (trust) {
      cap.appendChild(el("span", "trust-rank t" + trust.rank, "T" + trust.rank));
      cap.appendChild(el("strong", null, actionTaint));
    } else {
      cap.appendChild(el("strong", null, actionTaint || "unknown"));
    }
    cap.appendChild(icon("arrowRight"));
    cap.appendChild(document.createTextNode("caps authority at "));
    cap.appendChild(el("strong", null, trustCap || available));
    card.appendChild(cap);

    var line2 = el("p", "cap-line");
    line2.appendChild(document.createTextNode("This action needs "));
    line2.appendChild(el("strong", null, required));
    line2.appendChild(document.createTextNode(" and has "));
    line2.appendChild(el("strong", null, available));
    if (trustCap && AUTHORITY.indexOf(available) < AUTHORITY.indexOf(trustCap)) {
      line2.appendChild(document.createTextNode(" — narrowed below the trust ceiling by policy (the tool is not in this task's permitted set)."));
    }
    card.appendChild(line2);

    var ladder = el("div", "ladder");
    var reqIndex = AUTHORITY.indexOf(required);
    var availIndex = AUTHORITY.indexOf(available);
    AUTHORITY.forEach(function (level, index) {
      var rung = el("div", "rung");
      var isAvailable = index <= availIndex && index > 0;
      var isGap = index > availIndex && index <= reqIndex;
      if (isAvailable) rung.className = "rung available";
      if (isGap) rung.className = "rung gap";
      rung.appendChild(el("span", "rung-name", level));
      var flags = [];
      if (index === reqIndex) flags.push("required");
      if (index === availIndex && index > 0) flags.push("ceiling");
      rung.appendChild(el("span", "rung-flag", flags.join(" · ") || AUTHORITY_BLURB[level]));
      ladder.appendChild(rung);
    });
    card.appendChild(ladder);

    var verdict = el("div", "verdict-line");
    verdict.appendChild(pill(
      satisfied ? "authority satisfied" : "authority gap: needs " + required + ", has " + available,
      satisfied ? "good" : "bad",
      satisfied ? "check" : "warn"));
    if (authority.requires_confirmation) {
      verdict.appendChild(pill(
        authority.confirmation_present ? "human confirmation on record" : "human confirmation missing",
        authority.confirmation_present ? "good" : "bad",
        authority.confirmation_present ? "check" : "warn"));
    }
    if (authority.safer_alternative) {
      verdict.appendChild(pill("safer alternative: " + authority.safer_alternative, "warn", "arrowRight"));
    }
    card.appendChild(verdict);

    var grid = el("div", "kv-grid");
    var rows = [
      ["lifecycle stage", authority.lifecycle_stage || "—"],
      ["context taint", taint.context_taint || "—"],
      ["max sensitivity", taint.max_sensitivity || "—"],
      ["secrets seen", taint.secret_values_seen === undefined ? "—" : String(taint.secret_values_seen)],
      ["memory taint", taint.memory_taint || "none"],
      ["args from untrusted text", taint.value_derived_from_untrusted ? "yes" : "no"]
    ];
    rows.forEach(function (pair) {
      var kv = el("dl", "kv");
      kv.appendChild(el("dt", null, pair[0]));
      kv.appendChild(el("dd", null, pair[1]));
      grid.appendChild(kv);
    });
    card.appendChild(grid);
    return card;
  }

  function chainCard(step) {
    var card = sectionCard("Provenance chain — what influenced this action");
    var chain = (step.taint && step.taint.chain) || [];
    if (!chain.length) {
      card.appendChild(el("p", "hint", "Nothing untrusted influenced this step; the action stands on the user's own request."));
      return card;
    }
    var worst = 0;
    chain.forEach(function (link) {
      var t = TRUST_BY_ID[link.trust_level];
      if (t && t.rank > worst) worst = t.rank;
    });

    var flagged = false;
    var box = el("div", "chain");
    chain.forEach(function (link) {
      var t = TRUST_BY_ID[link.trust_level] || { rank: 0, band: "?", short: link.trust_level };
      var isWeakest = t.rank === worst && worst >= 3;
      var row = el("div", "link" + (isWeakest ? " weakest" : ""));

      var trust = el("div", "trust t" + t.rank);
      trust.appendChild(el("span", "trust-rank t" + t.rank, "T" + t.rank));
      var bar = el("span", "trust-bar");
      for (var i = 1; i <= 6; i++) {
        bar.appendChild(el("i", i <= t.rank ? "on" : null));
      }
      trust.appendChild(bar);
      trust.appendChild(el("span", "link-trust-name", "grants " + (t.band || "?")));
      row.appendChild(trust);

      var body = el("div", "link-body");
      var head = el("div", "link-head");
      head.appendChild(el("span", "link-source", link.source || link.provenance_id || "?"));
      head.appendChild(el("span", "link-trust-name", link.trust_level));
      head.appendChild(el("span", "rel", titleize(link.relation || "influence")));
      if (link.origin_actor) head.appendChild(el("span", "link-trust-name", "via " + link.origin_actor));
      if (link.sensitivity) head.appendChild(el("span", "tag", link.sensitivity));
      body.appendChild(head);
      if (link.excerpt) body.appendChild(el("div", "excerpt", link.excerpt));
      if (isWeakest && !flagged) {
        flagged = true;
        var flag = el("span", "weak-flag");
        flag.appendChild(icon("warn"));
        flag.appendChild(el("span", null, "weakest link — sets the ceiling"));
        body.appendChild(flag);
      }
      row.appendChild(body);
      box.appendChild(row);
    });
    card.appendChild(box);
    card.appendChild(el("p", "hint",
      "Trust ranks run T1 (system policy) to T6 (adversary-controlled). The lowest-trust link in this chain caps what the action may do — the text itself is never obeyed as an instruction."));
    return card;
  }

  function signalDetail(name, detail) {
    var frag = document.createDocumentFragment();
    if (!detail || typeof detail !== "object") return frag;

    if (Array.isArray(detail.matches) && detail.matches.length) {
      detail.matches.forEach(function (match) {
        var row = el("div", "match-row");
        row.appendChild(el("span", null, "secret " + (match.secret || "?")));
        var arrow = el("span", "match-arrow");
        arrow.appendChild(icon("arrowRight"));
        row.appendChild(arrow);
        row.appendChild(el("span", null, (match.transform || "encoded") + " transform"));
        row.appendChild(el("span", "match-arrow"));
        row.appendChild(el("span", null, "argument “" + (match.argument || "?") + "”"));
        frag.appendChild(row);
      });
    }

    var keys = Object.keys(detail).filter(function (k) { return k !== "matches"; });
    if (keys.length) {
      var table = el("table", "detail-table");
      keys.forEach(function (key) {
        var tr = el("tr");
        tr.appendChild(el("th", null, titleize(key)));
        tr.appendChild(el("td", null, fmtValue(detail[key])));
        table.appendChild(tr);
      });
      frag.appendChild(table);
    }
    return frag;
  }

  function signalsCard(step) {
    var card = sectionCard("Signals");
    var signals = (step.signals || []).slice().sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    if (!signals.length) {
      card.appendChild(el("p", "hint", "No signal reported for this step."));
      return card;
    }
    signals.forEach(function (signal) {
      var hot = (signal.score || 0) >= 0.4;
      var row = el("div", "signal" + (signal.score ? "" : " quiet"));
      var head = el("div", "signal-head");
      head.appendChild(el("span", "signal-name", signal.name));
      (signal.reason_codes || []).forEach(function (code) {
        head.appendChild(el("span", "code" + (hot ? " hot" : ""), code));
      });
      head.appendChild(el("span", "signal-score", num(signal.score)));
      row.appendChild(head);
      var bar = el("div", "signal-bar");
      var fill = el("span", hot ? "hot" : null);
      fill.style.width = (clamp01(signal.score) * 100).toFixed(1) + "%";
      bar.appendChild(fill);
      row.appendChild(bar);
      // A signal that saw nothing needs no evidence table; keep the panel scannable.
      if ((signal.score || 0) > 0 || (signal.reason_codes || []).length) {
        row.appendChild(signalDetail(signal.name, signal.detail));
      }
      card.appendChild(row);
    });
    return card;
  }

  function monitorCard(step) {
    var card = sectionCard("Calibrated monitor — why this number");
    var monitor = step.monitor;
    if (!monitor) {
      card.appendChild(el("p", "hint", "No monitor report for this step (ablation, or the arbiter used fixed weights)."));
      return card;
    }
    var grid = el("div", "kv-grid");
    [["mode", monitor.mode || "—"],
     ["monitor p", monitor.p === undefined ? "—" : num(monitor.p, 4)],
     ["damping", monitor.damp === undefined ? "—" : num(monitor.damp, 2)],
     ["final risk", num(step.risk_score, 4)]].forEach(function (pair) {
      var kv = el("dl", "kv");
      kv.appendChild(el("dt", null, pair[0]));
      kv.appendChild(el("dd", null, String(pair[1])));
      grid.appendChild(kv);
    });
    card.appendChild(grid);

    var rows = (monitor.top_contributions || []).filter(function (r) { return Array.isArray(r); });
    if (rows.length) {
      card.appendChild(el("h3", null, "Feature contributions"));
      var maxAbs = 0;
      rows.forEach(function (r) { maxAbs = Math.max(maxAbs, Math.abs(Number(r[1]) || 0)); });
      if (maxAbs <= 0) maxAbs = 1;
      var anyNeg = rows.some(function (r) { return (Number(r[1]) || 0) < 0; });
      var box = el("div", "contrib");
      rows.forEach(function (r) {
        var value = Number(r[1]) || 0;
        var line = el("div", "contrib-row");
        line.appendChild(el("span", "contrib-name", r[0]));
        var track = el("div", "contrib-track");
        var zero = el("div", "contrib-zero");
        zero.style.left = anyNeg ? "50%" : "0%";
        track.appendChild(zero);
        var fill = el("div", "contrib-fill" + (value < 0 ? " neg" : ""));
        var span = (Math.abs(value) / maxAbs) * (anyNeg ? 50 : 100);
        if (value < 0) {
          fill.style.right = "50%";
          fill.style.width = span + "%";
        } else {
          fill.style.left = anyNeg ? "50%" : "0%";
          fill.style.width = span + "%";
        }
        track.appendChild(fill);
        line.appendChild(track);
        line.appendChild(el("span", "contrib-value", (value > 0 ? "+" : "") + num(value, 3)));
        box.appendChild(line);
      });
      card.appendChild(box);
      card.appendChild(el("p", "hint",
        anyNeg ? "Bars right of the centre line pushed risk up; bars left pulled it down."
               : "Every bar is the share this feature contributed to the monitor's score."));
    }
    return card;
  }

  function outcomeCard(run, step) {
    var card = sectionCard("What happened next");
    var o = step.outcome;
    if (!o) {
      card.appendChild(el("p", "hint",
        "No simulator outcome joined for this step. Rebuild with --artifacts <path to starter/artifacts> to attach it."));
      return card;
    }
    var row = el("div", "outcome-row");
    var executed = o.executed === true;
    row.appendChild(pill(
      executed ? "tool executed" : "no tool executed",
      executed ? (o.legitimate === false ? "bad" : "good") : (step.decision === "allow" ? null : "good"),
      executed ? "check" : "slash"));
    if (o.legitimate !== undefined && o.legitimate !== null) {
      row.appendChild(pill(o.legitimate ? "legitimate action" : "not in the reference plan",
        o.legitimate ? "good" : "bad", o.legitimate ? "check" : "warn"));
    }
    if (o.consequential) row.appendChild(pill("consequential", "warn", "warn"));
    if (o.human_approved !== undefined && o.human_approved !== null) {
      row.appendChild(pill(o.human_approved ? "human approved" : "human denied",
        o.human_approved ? "good" : "bad", o.human_approved ? "check" : "cross"));
    }
    card.appendChild(row);

    if (Array.isArray(o.effects) && o.effects.length) {
      var list = el("ul", "effect-list");
      o.effects.forEach(function (effect) {
        var li = el("li");
        li.appendChild(icon("arrowRight"));
        li.appendChild(el("span", null, effect));
        list.appendChild(li);
      });
      card.appendChild(el("h3", null, "World effects"));
      card.appendChild(list);
    } else if (executed) {
      card.appendChild(el("p", "hint", "Executed with no state-changing effect (a read)."));
    } else {
      card.appendChild(el("p", "hint",
        step.decision === "block"
          ? "The action never reached the tool gateway: nothing changed in the world."
          : "Nothing was executed at this step."));
    }

    if (o.result_excerpt) {
      card.appendChild(el("h3", null, "Tool result"));
      card.appendChild(el("div", "block-text", o.result_excerpt));
    }
    if (o.response) {
      card.appendChild(el("h3", null, "Agent's answer to the user"));
      card.appendChild(el("div", "block-text", o.response));
    }
    if (Array.isArray(o.findings) && o.findings.length) {
      card.appendChild(el("h3", null, "Evaluator findings"));
      o.findings.forEach(function (finding) {
        card.appendChild(el("div", "block-text", fmtValue(finding)));
      });
    }
    if (o.task_summary) {
      card.appendChild(el("p", "hint", "Run result: " + o.task_summary));
    }
    return card;
  }

  function graderCard(run) {
    if (!run.outcome || !Array.isArray(run.outcome.grader_results) || !run.outcome.grader_results.length) return null;
    var card = sectionCard("Run success conditions (the simulator's own grader)");
    run.outcome.grader_results.forEach(function (result) {
      var row = el("div", "outcome-row");
      row.appendChild(pill(result.passed ? "pass" : "fail", result.passed ? "good" : "bad",
        result.passed ? "check" : "cross"));
      row.appendChild(el("span", "arg-val", result.condition || ""));
      card.appendChild(row);
      if (result.detail) card.appendChild(el("p", "hint", result.detail));
    });
    return card;
  }

  function renderDetail() {
    var host = document.getElementById("detail-inner");
    clear(host);
    var run = currentRun();
    var step = currentStep();
    if (!run || !step) {
      host.appendChild(el("p", "empty", "Pick a step to see the decision."));
      return;
    }
    var banner = healthBanner();
    if (banner) host.appendChild(banner);
    host.appendChild(headlineCard(run, step));

    var cols = el("div", "detail-cols");
    var left = el("div", "detail-col");
    var right = el("div", "detail-col");
    left.appendChild(authorityCard(step));
    left.appendChild(chainCard(step));
    left.appendChild(actionCard(step));
    right.appendChild(outcomeCard(run, step));
    right.appendChild(signalsCard(step));
    right.appendChild(monitorCard(step));
    var grader = graderCard(run);
    if (grader) right.appendChild(grader);
    cols.appendChild(left);
    cols.appendChild(right);
    host.appendChild(cols);
  }

  /* --------------------------------------------------------- summary view */

  function tile(value, label, note, tone) {
    var node = el("div", "tile" + (tone ? " " + tone : ""));
    node.appendChild(el("div", "tile-value", value));
    node.appendChild(div_label(label));
    if (note) node.appendChild(el("div", "tile-note", note));
    return node;
  }
  function div_label(label) { return el("div", "tile-label", label); }

  function stackedRow(name, counts) {
    var total = DECISIONS.reduce(function (sum, d) { return sum + (counts[d] || 0); }, 0);
    var row = el("div", "stack-row");
    row.appendChild(el("span", "stack-name", titleize(name)));
    var bar = el("div", "stack-bar");
    bar.setAttribute("role", "img");
    bar.setAttribute("aria-label", DECISIONS.map(function (d) {
      return (counts[d] || 0) + " " + d;
    }).join(", "));
    DECISIONS.forEach(function (d) {
      var count = counts[d] || 0;
      if (!count) return;
      var seg = el("i", "d-" + d);
      seg.style.width = (count / total * 100) + "%";
      seg.title = count + " " + d;
      bar.appendChild(seg);
    });
    row.appendChild(bar);
    row.appendChild(el("span", "stack-total", String(total)));
    return row;
  }

  function healthBanner() {
    var health = (DATA.meta || {}).health || {};
    var errors = health.errors || 0;
    var warnings = health.warnings || 0;
    if (!errors && !warnings) return null;
    var box = el("div", "banner" + (errors ? " error" : ""));
    box.setAttribute("role", errors ? "alert" : "status");
    var head = el("div", "banner-head");
    head.appendChild(icon("warn"));
    head.appendChild(el("strong", null, errors
      ? "This build contains traces that may not be current"
      : "This build has incomplete data"));
    box.appendChild(head);
    box.appendChild(el("p", null,
      errors + " error(s), " + warnings + " warning(s). Details in the Summary view under “Data provenance”."));
    var problems = health.runs_with_problems || {};
    var names = Object.keys(problems).slice(0, 6);
    if (names.length) {
      var list = el("ul", "banner-list");
      names.forEach(function (runId) {
        problems[runId].forEach(function (problem) {
          list.appendChild(el("li", null, runId + " — " + problem.code + ": " + problem.message));
        });
      });
      box.appendChild(list);
    }
    return box;
  }

  function provenanceCard() {
    var meta = DATA.meta || {};
    var health = meta.health || {};
    var card = sectionCard("Data provenance — where this page's numbers come from");
    var grid = el("div", "kv-grid");
    [["built", meta.generated_at || "—"],
     ["traces emitted", shortTime(health.emitted_first) + "  →  " + shortTime(health.emitted_last)],
     ["trace directory", meta.trace_dir || "—"],
     ["simulator artifacts", meta.artifacts_dir || "not joined"],
     ["trace schema", meta.schema || "—"],
     ["runs joined to outcomes", (health.joined || 0) + " / " + (meta.run_count || 0)]].forEach(function (pair) {
      var kv = el("dl", "kv");
      kv.appendChild(el("dt", null, pair[0]));
      kv.appendChild(el("dd", null, String(pair[1])));
      grid.appendChild(kv);
    });
    card.appendChild(grid);

    var problems = health.runs_with_problems || {};
    var runIds = Object.keys(problems);
    if (runIds.length) {
      card.appendChild(el("h3", null, "Runs with data problems"));
      runIds.forEach(function (runId) {
        problems[runId].forEach(function (problem) {
          var row = el("div", "outcome-row");
          row.appendChild(pill(problem.level, problem.level === "error" ? "bad" : "warn", "warn"));
          row.appendChild(el("span", "arg-val", runId + " — " + problem.code));
          card.appendChild(row);
          card.appendChild(el("p", "hint", problem.message));
        });
      });
    } else {
      card.appendChild(el("p", "hint",
        "Every run carries the current trace schema, was written as a single tagged run instance, and matched a simulator artifact. Nothing here is stale."));
    }

    card.appendChild(el("h3", null, "Per run"));
    var table = el("table", "detail-table");
    var header = el("tr");
    ["run", "emitted", "outcome artifact"].forEach(function (name) {
      header.appendChild(el("th", null, name));
    });
    table.appendChild(header);
    (DATA.runs || []).forEach(function (run) {
      var tr = el("tr");
      tr.appendChild(el("td", null, run.scenario_id));
      tr.appendChild(el("td", null, (run.emitted_first || "—").replace("T", " ").slice(0, 19)));
      var source = run.outcome_source
        ? run.outcome_source.split("/").slice(-2)[0]
        : "none";
      tr.appendChild(el("td", null, source));
      table.appendChild(tr);
    });
    card.appendChild(table);
    return card;
  }

  function renderSummary() {
    var host = document.getElementById("summary");
    clear(host);
    var s = DATA.summary || {};
    var wrap = el("div", "summary-wrap");
    var banner = healthBanner();
    if (banner) wrap.appendChild(banner);

    var head = el("div");
    head.appendChild(el("h2", null, "Results across every traced run"));
    head.appendChild(el("p", "goal",
      "Each run is one scenario played end to end against AEGIS. Metrics below are computed from the traces in this build; task and attack outcomes come from the simulator's own graders."));
    wrap.appendChild(head);

    var outcomes = s.outcomes || {};
    var tiles = el("div", "tiles");
    tiles.appendChild(tile(String(s.runs || 0), "runs traced", (s.steps || 0) + " decisions"));
    tiles.appendChild(tile(outcomes.btu === null || outcomes.btu === undefined ? "n/a" : pct(outcomes.btu),
      "benign task utility", outcomes.benign + " benign runs", "good"));
    tiles.appendChild(tile(outcomes.asr === null || outcomes.asr === undefined ? "n/a" : pct(outcomes.asr),
      "attack success rate", outcomes.attacks + " attack runs", outcomes.asr ? "bad" : "good"));
    tiles.appendChild(tile(outcomes.cvr === null || outcomes.cvr === undefined ? "n/a" : pct(outcomes.cvr),
      "critical violation rate", "all joined runs", outcomes.cvr ? "bad" : "good"));
    tiles.appendChild(tile(pct(s.escalation_rate), "escalation rate", "of all decisions"));
    tiles.appendChild(tile(num((s.latency || {}).p95, 2) + " ms", "p95 latency",
      "median " + num((s.latency || {}).median, 2) + " ms"));
    wrap.appendChild(tiles);

    var decisions = s.decisions || {};
    var decTiles = el("div", "tiles");
    DECISIONS.forEach(function (d) {
      decTiles.appendChild(tile(String(decisions[d] || 0), d + " decisions",
        pct((decisions[d] || 0) / (s.steps || 1)) + " of steps"));
    });
    wrap.appendChild(decTiles);

    var cols = el("div", "two-col");

    var familyCard = sectionCard("Decisions by attack family");
    var legend = el("div", "legend");
    DECISIONS.forEach(function (d) {
      var item = el("span");
      item.appendChild(el("span", "swatch d-" + d));
      item.appendChild(el("span", null, d));
      legend.appendChild(item);
    });
    familyCard.appendChild(legend);
    var families = s.by_attack_family || {};
    Object.keys(families).sort(function (a, b) {
      if (a === "benign") return -1;
      if (b === "benign") return 1;
      return a.localeCompare(b);
    }).forEach(function (family) {
      familyCard.appendChild(stackedRow(family, families[family]));
    });
    familyCard.appendChild(el("p", "hint",
      "Benign families should be almost entirely allow; attack families are where blocks and rewrites belong."));
    cols.appendChild(familyCard);

    var domainCard = sectionCard("Decisions by domain");
    var legend2 = legend.cloneNode(true);
    domainCard.appendChild(legend2);
    var domains = s.by_domain || {};
    Object.keys(domains).sort().forEach(function (domain) {
      domainCard.appendChild(stackedRow(domain, domains[domain]));
    });
    cols.appendChild(domainCard);

    var histCard = sectionCard("Risk score distribution");
    var hist = s.risk_histogram || [];
    var maxCount = hist.reduce(function (m, b) { return Math.max(m, b.count); }, 1);
    var row = el("div", "hist");
    hist.forEach(function (bucket) {
      var col = el("div", "hist-col");
      col.title = bucket.count + " decisions with risk " + bucket.lo + "–" + bucket.hi;
      col.appendChild(el("b", null, bucket.count ? String(bucket.count) : ""));
      var bar = el("i", bucket.lo >= 0.7 ? "d-block" : (bucket.lo >= 0.3 ? "d-escalate" : null));
      bar.style.height = Math.max(2, (bucket.count / maxCount) * 100) + "%";
      col.appendChild(bar);
      row.appendChild(col);
    });
    histCard.appendChild(row);
    var axis = el("div", "hist-axis");
    hist.forEach(function (bucket) { axis.appendChild(el("span", null, bucket.lo.toFixed(1))); });
    histCard.appendChild(axis);
    histCard.appendChild(el("p", "hint hist-note",
      "Risk is bimodal by design: benign work sits near zero, attacks sit above the block threshold. The middle band is where escalation to a human lives."));
    cols.appendChild(histCard);

    var reasonCard = sectionCard("Reason codes across all runs");
    var table = el("table", "reason-table");
    var reasons = s.reason_codes || [];
    var maxReason = reasons.reduce(function (m, r) { return Math.max(m, r[1]); }, 1);
    reasons.forEach(function (entry) {
      var tr = el("tr");
      var tdName = el("td");
      var button = el("button", "code", entry[0]);
      button.type = "button";
      button.addEventListener("click", function () {
        state.filters.reason = entry[0];
        state.view = "run";
        var hit = null;
        RUNS.forEach(function (r) {
          if (hit) return;
          r.steps.forEach(function (st) {
            if (!hit && (st.reason_codes || []).indexOf(entry[0]) >= 0) hit = [r, st];
          });
        });
        if (hit) { state.runId = hit[0].run_id; state.stepId = hit[1].step_id; }
        renderFilters(); render();
      });
      tdName.appendChild(button);
      tr.appendChild(tdName);
      var tdBar = el("td");
      var bar = el("div", "reason-bar");
      bar.style.width = Math.max(2, (entry[1] / maxReason) * 100) + "%";
      tdBar.appendChild(bar);
      tr.appendChild(tdBar);
      tr.appendChild(el("td", null, String(entry[1])));
      table.appendChild(tr);
    });
    reasonCard.appendChild(table);
    reasonCard.appendChild(el("p", "hint", "Pick a code to jump to the first step that carries it."));
    cols.appendChild(reasonCard);

    wrap.appendChild(cols);
    wrap.appendChild(provenanceCard());
    host.appendChild(wrap);
  }

  /* -------------------------------------------------------------- actions */

  function selectRun(runId, stepId) {
    var run = RUN_BY_ID[runId];
    if (!run) return;
    state.runId = runId;
    state.view = "run";
    if (stepId === null || stepId === undefined) {
      var headline = run.headline_step;
      state.stepId = headline !== null && headline !== undefined
        ? headline
        : (run.steps[0] ? run.steps[0].step_id : null);
    } else {
      state.stepId = stepId;
    }
    render();
  }

  function selectStep(stepId) {
    state.stepId = stepId;
    state.view = "run";
    render();
  }

  function moveStep(delta) {
    var run = currentRun();
    if (!run) return;
    var steps = run.steps.filter(stepMatchesFilters);
    if (!steps.length) steps = run.steps;
    var index = -1;
    for (var i = 0; i < steps.length; i++) {
      if (steps[i].step_id === state.stepId) { index = i; break; }
    }
    var next = Math.max(0, Math.min(steps.length - 1, (index < 0 ? 0 : index) + delta));
    selectStep(steps[next].step_id);
  }

  function moveRun(delta) {
    var runs = visibleRuns();
    if (!runs.length) return;
    var index = -1;
    for (var i = 0; i < runs.length; i++) {
      if (runs[i].run_id === state.runId) { index = i; break; }
    }
    var next = (index < 0 ? 0 : index + delta + runs.length) % runs.length;
    selectRun(runs[next].run_id, null);
  }

  function jumpInteresting(delta) {
    var run = currentRun();
    if (!run) return;
    var marks = run.steps.filter(function (s) { return s.decision !== "allow"; });
    if (!marks.length) return;
    var target = marks[0];
    if (delta > 0) {
      for (var i = 0; i < marks.length; i++) {
        if (marks[i].step_id > state.stepId) { target = marks[i]; break; }
      }
    } else {
      for (var j = marks.length - 1; j >= 0; j--) {
        if (marks[j].step_id < state.stepId) { target = marks[j]; break; }
      }
    }
    selectStep(target.step_id);
  }

  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try { localStorage.setItem("aegis-theme", theme); } catch (e) { /* ignore */ }
    var button = document.getElementById("theme-toggle");
    if (button) button.textContent = theme === "light" ? "Dark" : "Light";
  }

  function togglePresenter() {
    state.presenter = !state.presenter;
    document.body.classList.toggle("presenter", state.presenter);
    var button = document.getElementById("presenter-toggle");
    if (button) button.setAttribute("aria-pressed", state.presenter ? "true" : "false");
  }

  function toggleSummary() {
    state.view = state.view === "summary" ? "run" : "summary";
    render();
  }

  /* --------------------------------------------------------------- render */

  function render() {
    document.body.classList.toggle("summary-view", state.view === "summary");
    document.getElementById("summary").hidden = state.view !== "summary";
    document.getElementById("detail-inner").hidden = state.view === "summary";
    var footer = document.getElementById("footer-nav");
    if (footer) footer.hidden = state.view === "summary";
    var summaryButton = document.getElementById("summary-toggle");
    if (summaryButton) summaryButton.setAttribute("aria-pressed", state.view === "summary" ? "true" : "false");

    renderRail();
    renderSteps();
    if (state.view === "summary") {
      renderSummary();
    } else {
      renderDetail();
      var position = document.getElementById("step-position");
      var run = currentRun();
      var step = currentStep();
      if (position && run && step) {
        position.textContent = "step " + step.step_id + " / " + run.steps.length + " · " + run.scenario_id;
      }
      var current = document.querySelector('.step-item[aria-current="true"]');
      if (current && current.scrollIntoView) current.scrollIntoView({ block: "nearest" });
      var detail = document.querySelector(".detail");
      if (detail) detail.scrollTop = 0;
    }
    writeHash();
  }

  /* ----------------------------------------------------------------- boot */

  function bindControls() {
    document.getElementById("search").addEventListener("input", function (event) {
      state.filters.query = event.target.value || "";
      renderRail();
    });
    document.getElementById("theme-toggle").addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme");
      setTheme(current === "light" ? "dark" : "light");
    });
    document.getElementById("presenter-toggle").addEventListener("click", togglePresenter);
    document.getElementById("summary-toggle").addEventListener("click", toggleSummary);
    document.getElementById("rail-toggle").addEventListener("click", function () {
      document.body.classList.toggle("rail-open");
    });
    document.getElementById("prev-step").addEventListener("click", function () { moveStep(-1); });
    document.getElementById("next-step").addEventListener("click", function () { moveStep(1); });
    document.getElementById("next-flag").addEventListener("click", function () { jumpInteresting(1); });

    document.addEventListener("keydown", function (event) {
      var tag = (event.target && event.target.tagName) || "";
      if (tag === "INPUT" || tag === "TEXTAREA") {
        if (event.key === "Escape") event.target.blur();
        return;
      }
      if (event.metaKey || event.ctrlKey || event.altKey) return;
      switch (event.key) {
        case "ArrowRight": case "j": moveStep(1); event.preventDefault(); break;
        case "ArrowLeft": case "k": moveStep(-1); event.preventDefault(); break;
        case "ArrowDown": case "]": moveRun(1); event.preventDefault(); break;
        case "ArrowUp": case "[": moveRun(-1); event.preventDefault(); break;
        case "b": jumpInteresting(1); event.preventDefault(); break;
        case "p": togglePresenter(); event.preventDefault(); break;
        case "s": toggleSummary(); event.preventDefault(); break;
        case "t": setTheme(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light"); break;
        case "/": document.getElementById("search").focus(); event.preventDefault(); break;
        default: break;
      }
    });

    window.addEventListener("hashchange", function () {
      if (readHash()) render();
    });
  }

  function boot() {
    try {
      var saved = localStorage.getItem("aegis-theme");
      if (saved === "light" || saved === "dark") setTheme(saved);
    } catch (e) { /* storage unavailable — dark default stands */ }

    var meta = DATA.meta || {};
    var stamp = document.getElementById("build-stamp");
    if (stamp) {
      var health = meta.health || {};
      var emitted = (health.emitted_last || "").replace("T", " ").slice(0, 16);
      stamp.textContent = (meta.run_count || RUNS.length) + " runs · " +
        (meta.step_count || 0) + " decisions · traces " + (emitted || "unknown") +
        " · built " + (meta.generated_at || "");
      if (health.errors) stamp.className = "brand-sub stamp-error";
    }

    if (!RUNS.length) {
      document.getElementById("detail-inner").appendChild(
        el("p", "empty", "No traces in this build. Run the defense, then rebuild with python -m aegis.trace.viewer traces/"));
      return;
    }

    bindControls();
    renderFilters();
    if (!readHash()) {
      var preferred = meta.default_run && RUN_BY_ID[meta.default_run] ? meta.default_run : RUNS[0].run_id;
      state.runId = preferred;
      var run = RUN_BY_ID[preferred];
      state.stepId = run.headline_step !== null && run.headline_step !== undefined
        ? run.headline_step : run.steps[0].step_id;
    }
    render();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
})();
