#!/usr/bin/env python3
"""Light desktop view of one session scored by a safeguard bundle (Tkinter + matplotlib).

  python3 TCN-gui/tcn_gui.py [--bundle DIR] [--input NPZ|DIR] [--diagnostic]
  python3 TCN-gui/tcn_gui.py --bundle DIR --input NPZ --png out.png    # no window

One figure, four panels:
  1. anomaly score over time, calibrated threshold, k-of-n alarms, operational events
  2. memory chromatogram: per-bin prediction error over time (where in RAM it is unusual)
  3. how the network learned: train/dev loss per epoch, selected epoch
  4. workload classification over time (classifier probabilities)

Scores come from safeguard.runtime.Detector (analyza.py), the same as the live
detector. An anomaly is a deviation from benign training data, not a malware verdict.
"""
import argparse
from pathlib import Path
import sys

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import analyza  # noqa: E402

COLORS = {"ok": "#1f9d55", "alarm": "#d1343a", "unknown": "#d98a00", "error": "#d1343a"}
CLASS_COLORS = ["#2f6fde", "#e0a100", "#1f9d55", "#7b5cd6", "#d1343a", "#5d6673", "#14a3b8", "#b85c14"]


def _spans(t, flags, step):
    out, start = [], None
    for i, flag in enumerate(flags):
        if flag and start is None:
            start = t[i]
        if start is not None and (not flag or i == len(flags) - 1):
            out.append((start, (t[i] if flag else t[i - 1]) + step))
            start = None
    return out


def draw(fig, report):
    """Render the report into a matplotlib figure (used by the window and by --png)."""
    from matplotlib.colors import LogNorm

    fig.clear()
    grid = fig.add_gridspec(3, 2, height_ratios=[1.0, 1.25, 1.0], hspace=0.55, wspace=0.22,
                            left=0.07, right=0.93, top=0.9, bottom=0.08)
    s, verdict = report["series"], report["verdict"]
    t0 = s["t"][0] if s["t"] else 0.0
    minutes = np.array([(t - t0) / 60 for t in s["t"]])
    step = (minutes[1] - minutes[0]) if len(minutes) > 1 else 0.1
    score = np.array([np.nan if v is None else v for v in s["score"]])
    summary = report["summary"]
    context = report["input"]["context"]
    name = context.get("session_id") or Path(report["input"]["session_dir"]).name
    fig.suptitle(f"{verdict['label']}  ·  {name}  ·  model {report['model']['name']}",
                 color=COLORS[verdict["level"]], fontsize=14, fontweight="bold", x=0.07, ha="left")
    fig.text(0.07, 0.935, verdict["detail"], fontsize=9, color="#5d6673", ha="left")

    # 1. Score over time.
    ax = fig.add_subplot(grid[0, :])
    for a, b in _spans(minutes, s["model_alarm"], step):
        ax.axvspan(a, b, color=COLORS["alarm"], alpha=0.15, lw=0)
    for e in context.get("events", []):
        if e.get("start") and e.get("stop"):
            a, b = (e["start"] - t0) / 60, (e["stop"] - t0) / 60
            ax.axvspan(a, b, color="#7b5cd6", alpha=0.15 if e.get("executed") else 0.05, lw=0)
            ax.text(a, 1.0, " " + str(e.get("type")), transform=ax.get_xaxis_transform(),
                    fontsize=7, color="#7b5cd6", va="bottom")
    ax.plot(minutes, score, color="#2f6fde", lw=1.2, label="skóre okna")
    ax.axhline(report["threshold"], color=COLORS["alarm"], ls="--", lw=1, label=f"prah {report['threshold']:.4g}")
    hits = [m for m, f in zip(minutes, s["integrity"]) if f]
    if hits:
        ax.plot(hits, [np.nanmax(score) if np.isfinite(score).any() else report["threshold"]] * len(hits),
                "x", color=COLORS["alarm"], label="nález integrity")
    finite = score[np.isfinite(score)]
    if finite.size and finite.max() > 20 * max(np.median(finite), 1e-9):
        ax.set_yscale("log")
    ax.set_title(f"Skóre anomálie · {summary['scored']} okien, {summary['above_threshold']} nad prahom, "
                 f"{summary['model_alarm_events']} alarmov (pravidlo {report['k']} z {report['n']})",
                 fontsize=10, loc="left")
    ax.set_ylabel("skóre")
    ax.set_xlim(0, minutes[-1] + step if len(minutes) else 1)
    ax.legend(loc="upper right", fontsize=8, frameon=False)
    ax.grid(alpha=0.25)

    # 2. Memory chromatogram.
    ax2 = fig.add_subplot(grid[1, :], sharex=ax)
    bins = report["bins"]
    z = np.array([[np.nan if row is None or row[b] is None else row[b] for row in bins["errors"]]
                  for b in range(len(bins["ids"]))], dtype=float)
    if np.isfinite(z).any():
        positive = z[np.isfinite(z) & (z > 0)]
        norm = LogNorm(vmin=max(positive.min(), np.percentile(positive, 1)), vmax=positive.max()) if positive.size else None
        image = ax2.imshow(z, aspect="auto", interpolation="nearest", cmap="inferno", norm=norm,
                           extent=(0, minutes[-1] + step, len(bins["ids"]), 0))
        bar = ax2.inset_axes([1.008, 0, 0.012, 1])  # Outside the axes, so panels 1 and 2 keep one time axis.
        fig.colorbar(image, cax=bar).set_label("chyba binu (log)", fontsize=8)
    ticks = np.linspace(0, len(bins["ids"]) - 1, min(8, len(bins["ids"]))).astype(int)
    ax2.set_yticks(ticks + 0.5, [f"{bins['gpa_mib'][i]:.0f}" for i in ticks], fontsize=8)
    ax2.set_ylabel("GPA [MiB]")
    ax2.set_xlabel("minúty od začiatku session")
    worst = [b for b in bins["top_by_mean"][:3] if bins["mean_error"][b] is not None]
    ax2.set_title("Pamäťový chromatogram · chyba predikcie per-bin TCN (do skóre ide najhorší bin) · "
                  "najrelevantnejšie: " + ", ".join(f"{bins['gpa_mib'][b]:.0f} MiB" for b in worst),
                  fontsize=10, loc="left")

    # 3. How the network learned.
    ax3 = fig.add_subplot(grid[2, 0])
    model = report["model"]
    history = model.get("history") or []
    epochs = [h["epoch"] for h in history]
    ax3.plot(epochs, [h["train_prediction_loss"] for h in history], "o-", color="#2f6fde", ms=3, label="predikcia train")
    ax3.plot(epochs, [h["dev_prediction_loss"] for h in history], "o-", color="#e0a100", ms=3, label="predikcia dev")
    ax3b = ax3.twinx()
    ax3b.plot(epochs, [h["train_classification_loss"] for h in history], "s--", color="#2f6fde", ms=3, alpha=0.6,
              label="klasifikácia train")
    ax3b.plot(epochs, [h["dev_classification_loss"] for h in history], "s--", color="#e0a100", ms=3, alpha=0.6,
              label="klasifikácia dev")
    if model.get("selected_predictor_epoch"):
        ax3.axvline(model["selected_predictor_epoch"], color=COLORS["ok"], ls=":", lw=1.2)
    from matplotlib.ticker import MaxNLocator
    ax3.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax3.set_xlabel("epocha")
    ax3.set_ylabel("strata predikcie")
    ax3b.set_ylabel("strata klasifikácie", fontsize=8)
    windows = model.get("windows") or {}
    ax3.set_title(f"Učenie siete · vybraná epocha {model.get('selected_predictor_epoch')}/{model.get('epochs')} · "
                  + ", ".join(f"{k} {v}" for k, v in windows.items()) + " okien", fontsize=10, loc="left")
    lines = ax3.get_legend_handles_labels()
    lines2 = ax3b.get_legend_handles_labels()
    ax3.legend(lines[0] + lines2[0], lines[1] + lines2[1], fontsize=7, frameon=False, loc="upper right")
    ax3.grid(alpha=0.25)

    # 4. Classification over time.
    ax4 = fig.add_subplot(grid[2, 1])
    classes = list(s["activity"])
    stack = np.array([[np.nan if v is None else v for v in s["activity"][c]] for c in classes], dtype=float)
    valid = np.isfinite(stack).all(axis=0)
    if valid.any():
        ax4.stackplot(minutes[valid], np.nan_to_num(stack[:, valid]), labels=classes,
                      colors=CLASS_COLORS[:len(classes)], alpha=0.85)
        mean = stack[:, valid].mean(axis=1)
        top = classes[int(np.argmax(mean))]
        expected = context.get("scenario")
        note = f" · zaznamenaný scenár: {expected}" if expected else ""
        ax4.set_title(f"Klasifikácia záťaže · prevažuje {top} ({mean.max():.0%}){note}", fontsize=10, loc="left")
    ax4.set_ylim(0, 1)
    ax4.set_xlim(0, minutes[-1] + step if len(minutes) else 1)
    ax4.set_xlabel("minúty")
    ax4.set_ylabel("pravdepodobnosť")
    ax4.legend(fontsize=7, frameon=False, loc="lower left", ncol=min(3, len(classes)))
    fig.text(0.07, 0.01, "Anomália = odchýlka od benígnej prevádzky z tréningu, nie verdikt o malvéri. "
             "Klasifikátor opisuje druh záťaže, nie škodlivosť.", fontsize=8, color="#5d6673")
    return fig


def window(bundle=None, source=None, diagnostic=False):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
    from matplotlib.figure import Figure

    root = tk.Tk()
    root.title("TCN detektor")
    root.geometry("1400x950")
    state = {"bundle": tk.StringVar(value=bundle or ""), "input": tk.StringVar(value=source or ""),
             "diagnostic": tk.BooleanVar(value=diagnostic), "status": tk.StringVar()}
    bar = ttk.Frame(root, padding=6)
    bar.pack(side="top", fill="x")

    def choose_bundle():
        path = filedialog.askdirectory(title="Adresár modelu (manifest.json)", initialdir=analyza.ROOT / "data")
        if path:
            state["bundle"].set(path)

    def choose_file():
        path = filedialog.askopenfilename(title="Archív príznakov session", initialdir=analyza.ROOT / "data",
                                          filetypes=[("archív príznakov", "*.npz"), ("všetko", "*")])
        if path:
            state["input"].set(path)

    def choose_dir():
        path = filedialog.askdirectory(title="Adresár session alebo snímok .vmicd", initialdir=analyza.ROOT / "data")
        if path:
            state["input"].set(path)

    ttk.Button(bar, text="Model…", command=choose_bundle).pack(side="left")
    ttk.Entry(bar, textvariable=state["bundle"], width=40).pack(side="left", padx=4)
    ttk.Button(bar, text="Snímky (.npz)…", command=choose_file).pack(side="left")
    ttk.Button(bar, text="Adresár…", command=choose_dir).pack(side="left", padx=(2, 0))
    ttk.Entry(bar, textvariable=state["input"], width=50).pack(side="left", padx=4)
    ttk.Checkbutton(bar, text="diagnostický balík", variable=state["diagnostic"]).pack(side="left")
    figure = Figure(figsize=(14, 9), dpi=100)
    canvas = FigureCanvasTkAgg(figure, master=root)

    def run():
        if not state["bundle"].get() or not state["input"].get():
            messagebox.showinfo("TCN detektor", "Vyber model aj snímky.")
            return
        if analyza.busy_collecting():
            messagebox.showwarning("TCN detektor", "Na tomto PC beží zber. Prehratie by zaťažilo CPU a disk "
                                   "a narušilo meranie; spusti analýzu po zbere alebo na inom PC.")
            return
        state["status"].set("Prehrávam session cez model…")
        root.config(cursor="watch")
        root.update_idletasks()
        try:
            report = analyza.analyze(state["bundle"].get(), state["input"].get(),
                                     allow_diagnostic=state["diagnostic"].get())
            draw(figure, report)
            canvas.draw_idle()
            state["status"].set(report["input"]["path"])
        except (ValueError, OSError, RuntimeError, KeyError) as exc:
            state["status"].set("")
            messagebox.showerror("TCN detektor", f"{type(exc).__name__}: {exc}")
        finally:
            root.config(cursor="")

    ttk.Button(bar, text="Analyzovať", command=run).pack(side="left", padx=6)
    ttk.Label(root, textvariable=state["status"], foreground="#5d6673", padding=(8, 0)).pack(side="top", fill="x")
    NavigationToolbar2Tk(canvas, root).pack(side="bottom", fill="x")
    canvas.get_tk_widget().pack(side="top", fill="both", expand=True)
    if bundle and source:
        root.after(100, run)
    root.mainloop()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bundle", help="adresár balíka safeguard (manifest.json)")
    parser.add_argument("--input", help="archív .npz, adresár session alebo adresár snímok .vmicd")
    parser.add_argument("--diagnostic", action="store_true", help="povoliť diagnostický (syntetický) balík")
    parser.add_argument("--png", type=Path, help="bez okna: uložiť obrázok sem")
    args = parser.parse_args(argv)
    if args.png:
        if not (args.bundle and args.input):
            parser.error("--png potrebuje --bundle aj --input")
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib.figure import Figure
        report = analyza.analyze(args.bundle, args.input, allow_diagnostic=args.diagnostic)
        draw(Figure(figsize=(14, 9), dpi=110), report).savefig(args.png)
        print(f"{report['verdict']['label']}: {args.png}")
        return 0
    window(args.bundle, args.input, args.diagnostic)
    return 0


if __name__ == "__main__":
    sys.exit(main())
