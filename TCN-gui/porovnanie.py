"""Compare several trained bundles (for example one per week) on one reference session.

Raw weights of two separately trained networks are not compared element by
element: channels can come out in any order, so their difference would show
mostly that permutation. Instead every view here is permutation invariant:

  score       each model's score / own threshold on the same session (1 = threshold)
  baseline    what each model treats as normal: its normalizer means, shifted
              against the first model and expressed in the first model's std units
  layers      linear CKA (Kornblith et al., 2019) between each TCN block's
              activations and the same block of the first model, on the same
              windows of the session (1 = same representation up to rotation)
  learning    dev prediction loss per epoch, selected epoch and threshold
"""
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import torch

import analyza
from safeguard.bundle import load_bundle
from safeguard.features import GLOBAL_NAMES, LOCAL_NAMES, WindowBuffer, arrays, frames_from_archive

MAX_WINDOWS = 400


def linear_cka(x, y):
    """Linear CKA of two activation matrices with the same rows (samples)."""
    x = x - x.mean(axis=0)
    y = y - y.mean(axis=0)
    cross = np.linalg.norm(y.T @ x) ** 2
    norm = np.linalg.norm(x.T @ x) * np.linalg.norm(y.T @ y)
    return float(cross / norm) if norm > 0 else float("nan")


def _windows(frames, window_rows, max_gap_s):
    buffer, out = WindowBuffer(window_rows, max_gap_s), {}
    for frame in frames:
        try:
            window = buffer.push(frame)
        except ValueError:
            continue
        if window is not None:
            out[int(frame.seq)] = window
    return out


def _activations(bundle, windows):
    """Last-step output of every TCN block, per layer, for the given windows."""
    g, local = zip(*(bundle.normalizer.transform(*arrays(w)) for w in windows))
    gt = torch.as_tensor(np.stack(g), dtype=torch.float32)
    lt = torch.as_tensor(np.stack(local), dtype=torch.float32)
    captured, hooks = {}, []
    layers = ([("prediktor globálny", b) for b in bundle.predictor.global_tcn.bloky]
              + [("prediktor per-bin", b) for b in bundle.predictor.bin_tcn.bloky]
              + [("klasifikátor", b) for b in bundle.classifier.tcn.bloky])
    names = []
    for i, (group, block) in enumerate(layers):
        index = sum(1 for g_, _ in layers[:i] if g_ == group) + 1
        name = f"{group} {index}"
        names.append(name)
        hooks.append(block.register_forward_hook(
            lambda _m, _i, out, name=name: captured.__setitem__(name, out[:, :, -1].detach().numpy())))
    try:
        with torch.inference_mode():
            bundle.predictor(gt[:, :-1], lt[:, :-1])
            bundle.classifier(gt, lt)
    finally:
        for hook in hooks:
            hook.remove()
    return names, captured


def compare(bundle_paths, input_path, *, allow_diagnostic=False):
    if len(bundle_paths) < 2:
        raise ValueError("na porovnanie treba aspoň dva modely")
    bundles = [(Path(p).resolve(), load_bundle(p, allow_diagnostic=allow_diagnostic)) for p in bundle_paths]
    bundles.sort(key=lambda item: item[1].manifest.get("created_utc", ""))
    kind, source, session_dir = analyza.resolve_input(input_path)
    if kind != "archive":
        raise ValueError("porovnanie modelov potrebuje archív príznakov session (.npz)")
    with np.load(source, allow_pickle=False) as data:
        frames = frames_from_archive(data, session_dir.name)

    models, reference = [], bundles[0][1]
    for path, bundle in bundles:
        report = analyza.analyze(path, source, bundle=bundle)
        info = report["model"]
        norm = bundle.normalizer
        ref = reference.normalizer
        shift = list((norm.global_mean - ref.global_mean) / ref.global_scale) + \
            list((norm.local_mean[:3] - ref.local_mean[:3]) / ref.local_scale[:3])
        models.append({
            "name": path.name, "path": str(path), "created_utc": info["created_utc"],
            "threshold": report["threshold"], "k": report["k"], "n": report["n"],
            "history": info["history"], "selected_epoch": info["selected_predictor_epoch"],
            "epochs": info["epochs"], "windows": info["windows"],
            "t": report["series"]["t"],
            "score_ratio": [None if s is None else s / report["threshold"] for s in report["series"]["score"]],
            "alarms": report["summary"]["model_alarm_events"], "verdict": report["verdict"]["label"],
            "baseline_shift": [float(v) for v in shift],
        })

    # Layer similarity on windows that every model can score.
    per_model = [_windows(frames, b.contract["window_rows"], b.contract["max_gap_s"]) for _, b in bundles]
    common = sorted(set.intersection(*(set(w) for w in per_model)))
    if len(common) > MAX_WINDOWS:
        common = [common[i] for i in np.linspace(0, len(common) - 1, MAX_WINDOWS).astype(int)]
    cka, layer_names, note = None, [], None
    if len(common) >= 10:
        acts = []
        for (_, bundle), windows in zip(bundles, per_model):
            names, captured = _activations(bundle, [windows[s] for s in common])
            acts.append((names, captured))
        layer_names = acts[0][0]
        cka = []
        for names, captured in acts:
            row = []
            for name in layer_names:
                if name in captured and name in acts[0][1] and captured[name].shape[0] == acts[0][1][name].shape[0]:
                    row.append(linear_cka(acts[0][1][name], captured[name]))
                else:
                    row.append(None)
            cka.append(row)
    else:
        note = "príliš málo spoločných okien na porovnanie vrstiev"

    return {
        "schema": "hyptcn3/tcn-gui-model-comparison/1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "input": {"path": str(source), "session": session_dir.name,
                  "context": analyza._session_context(session_dir)},
        "reference": models[0]["name"], "models": models,
        "baseline_names": list(GLOBAL_NAMES) + [f"bin {n}" for n in LOCAL_NAMES[:3]],
        "layers": {"names": layer_names, "cka": cka, "windows": len(common), "note": note},
    }


PALETTE = ["#2f6fde", "#e0a100", "#1f9d55", "#d1343a", "#7b5cd6", "#14a3b8", "#b85c14", "#5d6673"]


def draw_compare(fig, result):
    fig.clear()
    grid = fig.add_gridspec(2, 2, hspace=0.5, wspace=0.42, left=0.06, right=0.98, top=0.9, bottom=0.1,
                            width_ratios=[1.3, 1])
    models = result["models"]
    color = {m["name"]: PALETTE[i % len(PALETTE)] for i, m in enumerate(models)}
    fig.suptitle(f"Porovnanie {len(models)} modelov na session {result['input']['session']}",
                 fontsize=13, fontweight="bold", x=0.07, ha="left")

    ax = fig.add_subplot(grid[0, 0])
    for m in models:
        if not m["t"]:
            continue
        minutes = [(t - m["t"][0]) / 60 for t in m["t"]]
        ratio = [np.nan if v is None else v for v in m["score_ratio"]]
        ax.plot(minutes, ratio, lw=1.1, color=color[m["name"]],
                label=f"{m['name']}: {m['verdict'].lower()}, {m['alarms']} alarm")
    ax.axhline(1, color="#d1343a", ls="--", lw=1)
    finite = [v for m in models for v in m["score_ratio"] if v is not None]
    if finite and max(finite) > 20 * max(np.median(finite), 1e-9):
        ax.set_yscale("log")
    ax.set_title("Skóre / vlastný prah na tej istej session (nad 1 = nad prahom)", fontsize=10, loc="left")
    ax.set_xlabel("minúty")
    ax.legend(fontsize=7, frameon=False)
    ax.grid(alpha=0.25)

    ax2 = fig.add_subplot(grid[0, 1])
    names = result["baseline_names"]
    shown = models[1:] or models
    height = 0.8 / len(shown)
    y = np.arange(len(names))
    for i, m in enumerate(shown):
        ax2.barh(y + i * height, m["baseline_shift"], height=height, color=color[m["name"]], label=m["name"])
    ax2.axvline(0, color="#444", lw=0.8)
    ax2.set_yticks(y + height * (len(shown) - 1) / 2, names, fontsize=7)
    ax2.invert_yaxis()
    ax2.set_xlabel("posun priemeru [σ prvého modelu]")
    ax2.set_title("Čo model považuje za normálne\n(posun voči prvému modelu)", fontsize=10, loc="left")
    ax2.legend(fontsize=7, frameon=False, loc="lower right")
    ax2.grid(alpha=0.25, axis="x")

    ax3 = fig.add_subplot(grid[1, 0])
    layers = result["layers"]
    if layers["cka"]:
        x = np.arange(len(layers["names"]))
        for m, row in zip(models, layers["cka"]):
            ax3.plot(x, [np.nan if v is None else v for v in row], "o-", ms=3, color=color[m["name"]], label=m["name"])
        ax3.set_xticks(x, [n.replace("prediktor ", "").replace("klasifikátor", "klas.") for n in layers["names"]],
                       rotation=45, ha="right", fontsize=7)
        ax3.set_ylim(0, 1.05)
        ax3.set_title(f"Podobnosť vrstiev s modelom {result['reference']} (CKA, {layers['windows']} okien; 1 = rovnaké)",
                      fontsize=10, loc="left")
    else:
        ax3.text(0.5, 0.5, layers["note"] or "bez údajov", ha="center", va="center", transform=ax3.transAxes)
    ax3.grid(alpha=0.25)

    ax4 = fig.add_subplot(grid[1, 1])
    for m in models:
        epochs = [h["epoch"] for h in m["history"]]
        ax4.plot(epochs, [h["dev_prediction_loss"] for h in m["history"]], "o-", ms=3, color=color[m["name"]],
                 label=f"{m['name']}: prah {m['threshold']:.3g}")
        if m["selected_epoch"]:
            ax4.axvline(m["selected_epoch"], color=color[m["name"]], ls=":", lw=1)
    from matplotlib.ticker import MaxNLocator
    ax4.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax4.set_xlabel("epocha")
    ax4.set_ylabel("strata predikcie (dev)")
    ax4.set_title("Učenie (bodkovane: vybraná epocha)", fontsize=10, loc="left")
    ax4.legend(fontsize=7, frameon=False)
    ax4.grid(alpha=0.25)
    return fig
